package authchallenge

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/websocket"
)

// captureExternalLogin blocks the callback before it reaches the VPN server.
// The existing Go session, not the browser, must redeem its ticket/code.
func captureExternalLogin(challenge ExternalLoginChallenge, output io.Writer) (ExternalLoginResponse, error) {
	expected, err := url.Parse(challenge.CallbackURL)
	if err != nil || expected.Host == "" || expected.User != nil ||
		(expected.Scheme != "https" && expected.Scheme != "http") {
		return ExternalLoginResponse{}, fmt.Errorf("invalid callback endpoint")
	}
	key := "ticket"
	switch challenge.Kind {
	case ExternalLoginCAS:
	case ExternalLoginOAuth2:
		key = "code"
	default:
		return ExternalLoginResponse{}, fmt.Errorf("unsupported browser login kind")
	}

	candidates := []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome", "msedge"}
	switch runtime.GOOS {
	case "windows":
		for _, root := range []string{os.Getenv("PROGRAMFILES"), os.Getenv("PROGRAMFILES(X86)"), os.Getenv("LOCALAPPDATA")} {
			if root != "" {
				candidates = append(candidates,
					filepath.Join(root, "Google", "Chrome", "Application", "chrome.exe"),
					filepath.Join(root, "Microsoft", "Edge", "Application", "msedge.exe"))
			}
		}
	case "darwin":
		candidates = append(candidates,
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
			"/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
			"/Applications/Chromium.app/Contents/MacOS/Chromium")
	}
	var executable string
	for _, candidate := range candidates {
		if path, lookupErr := exec.LookPath(candidate); lookupErr == nil {
			executable = path
			break
		}
	}
	if executable == "" {
		return ExternalLoginResponse{}, fmt.Errorf("Chrome/Chromium/Edge not found")
	}
	profile, err := os.MkdirTemp("", "zju-connect-login-")
	if err != nil {
		return ExternalLoginResponse{}, err
	}
	defer os.RemoveAll(profile)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable,
		"--remote-debugging-address=127.0.0.1", "--remote-debugging-port=0",
		"--remote-allow-origins=http://localhost",
		"--user-data-dir="+profile, "--no-first-run", "--no-default-browser-check",
		"--disable-background-mode", "about:blank")
	if err := cmd.Start(); err != nil {
		return ExternalLoginResponse{}, fmt.Errorf("start browser: %w", err)
	}
	done := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(done)
	}()
	defer func() {
		_ = cmd.Process.Kill()
		<-done
	}()

	// Chrome writes a random loopback port and the browser websocket path here.
	var endpoint string
	startupDeadline := time.Now().Add(15 * time.Second)
	for endpoint == "" {
		data, readErr := os.ReadFile(filepath.Join(profile, "DevToolsActivePort"))
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		if readErr == nil && len(lines) >= 2 {
			port, portErr := strconv.Atoi(strings.TrimSpace(lines[0]))
			path := strings.TrimSpace(lines[1])
			if portErr == nil && port > 0 && port <= 65535 && strings.HasPrefix(path, "/devtools/browser/") {
				endpoint = "ws://127.0.0.1:" + strconv.Itoa(port) + path
				break
			}
		}
		if time.Now().After(startupDeadline) {
			return ExternalLoginResponse{}, fmt.Errorf("browser debugging endpoint timed out")
		}
		select {
		case <-done:
			return ExternalLoginResponse{}, fmt.Errorf("browser exited before debugging was ready")
		case <-ctx.Done():
			return ExternalLoginResponse{}, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	config, err := websocket.NewConfig(endpoint, "http://localhost")
	if err != nil {
		return ExternalLoginResponse{}, err
	}
	config.Dialer = &net.Dialer{Timeout: 5 * time.Second}
	conn, err := config.DialContext(ctx)
	if err != nil {
		return ExternalLoginResponse{}, fmt.Errorf("connect browser debugger: %w", err)
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return ExternalLoginResponse{}, err
	}
	defer func() {
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		_ = websocket.JSON.Send(conn, map[string]any{"id": 1000000000, "method": "Browser.close"})
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	}()

	type command struct {
		method    string
		sessionID string
		callback  string
	}
	pending := make(map[int]command)
	nextID := 0
	send := func(method, sessionID string, params any, callback string) error {
		nextID++
		pending[nextID] = command{method, sessionID, callback}
		return websocket.JSON.Send(conn, struct {
			ID        int    `json:"id"`
			Method    string `json:"method"`
			SessionID string `json:"sessionId,omitempty"`
			Params    any    `json:"params"`
		}{nextID, method, sessionID, params})
	}
	// Pause new pages (including login popups) until interception is installed.
	if err := send("Target.setAutoAttach", "", map[string]any{
		"autoAttach": true, "waitForDebuggerOnStart": true, "flatten": true,
	}, ""); err != nil {
		return ExternalLoginResponse{}, err
	}
	_, _ = fmt.Fprintln(output, "Complete login in the browser. Callback capture expires in 5 minutes; close the browser to return to manual input.")
	navigated := false
	for {
		var event struct {
			ID        int             `json:"id"`
			Method    string          `json:"method"`
			SessionID string          `json:"sessionId"`
			Params    json.RawMessage `json:"params"`
			Error     *struct {
				Code int `json:"code"`
			} `json:"error"`
		}
		if err := websocket.JSON.Receive(conn, &event); err != nil {
			return ExternalLoginResponse{}, fmt.Errorf("browser capture ended: %w", err)
		}
		if event.ID != 0 {
			request := pending[event.ID]
			delete(pending, event.ID)
			if event.Error != nil {
				return ExternalLoginResponse{}, fmt.Errorf("browser %s failed (%d)", request.method, event.Error.Code)
			}
			switch request.method {
			case "Fetch.enable":
				if err := send("Runtime.runIfWaitingForDebugger", request.sessionID, struct{}{}, ""); err != nil {
					return ExternalLoginResponse{}, err
				}
				if !navigated {
					navigated = true
					if err := send("Page.navigate", request.sessionID, map[string]any{"url": challenge.LoginURL}, ""); err != nil {
						return ExternalLoginResponse{}, err
					}
				}
			case "Fetch.failRequest":
				// Only hand off after Chrome acknowledges that it aborted.
				if request.callback != "" {
					callback, _ := url.Parse(request.callback)
					if callback.Query().Get(key) == "" {
						return ExternalLoginResponse{}, fmt.Errorf("callback is missing %s", key)
					}
					return ExternalLoginResponse{CallbackURL: request.callback}, nil
				}
			}
			continue
		}
		switch event.Method {
		case "Target.attachedToTarget":
			var attached struct {
				SessionID  string `json:"sessionId"`
				TargetInfo struct {
					Type string `json:"type"`
				} `json:"targetInfo"`
			}
			if err := json.Unmarshal(event.Params, &attached); err != nil {
				return ExternalLoginResponse{}, err
			}
			if attached.TargetInfo.Type != "page" && attached.TargetInfo.Type != "iframe" {
				if err := send("Runtime.runIfWaitingForDebugger", attached.SessionID, struct{}{}, ""); err != nil {
					return ExternalLoginResponse{}, err
				}
				continue
			}
			if err := send("Fetch.enable", attached.SessionID, map[string]any{
				"patterns": []map[string]string{{"urlPattern": "*", "requestStage": "Request"}},
			}, ""); err != nil {
				return ExternalLoginResponse{}, err
			}
		case "Fetch.requestPaused":
			var paused struct {
				RequestID string `json:"requestId"`
				Request   struct {
					URL string `json:"url"`
				} `json:"request"`
			}
			if err := json.Unmarshal(event.Params, &paused); err != nil {
				return ExternalLoginResponse{}, err
			}
			target, parseErr := url.Parse(paused.Request.URL)
			if parseErr == nil && target.User == nil &&
				strings.EqualFold(target.Scheme, expected.Scheme) &&
				strings.EqualFold(target.Host, expected.Host) && target.Path == expected.Path {
				// Never let the browser redeem even a malformed callback.
				if err := send("Fetch.failRequest", event.SessionID, map[string]any{
					"requestId": paused.RequestID, "errorReason": "Aborted",
				}, paused.Request.URL); err != nil {
					return ExternalLoginResponse{}, err
				}
			} else if err := send("Fetch.continueRequest", event.SessionID, map[string]any{
				"requestId": paused.RequestID,
			}, ""); err != nil {
				return ExternalLoginResponse{}, err
			}
		}
	}
}

package authchallenge

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

const defaultCaptchaTimeout = 5 * time.Minute

type CLIOptions struct {
	Input          io.Reader
	Output         io.Writer
	CaptchaTimeout time.Duration
}

type CLIHandler struct {
	input          *bufio.Reader
	output         io.Writer
	captchaTimeout time.Duration
	mu             sync.Mutex
}

func NewCLIHandler(options CLIOptions) *CLIHandler {
	input := options.Input
	if input == nil {
		input = os.Stdin
	}
	output := options.Output
	if output == nil {
		output = os.Stdout
	}
	timeout := options.CaptchaTimeout
	if timeout <= 0 {
		timeout = defaultCaptchaTimeout
	}
	return &CLIHandler{
		input:          bufio.NewReader(input),
		output:         output,
		captchaTimeout: timeout,
	}
}

func (h *CLIHandler) HandleCodeChallenge(challenge CodeChallenge) (CodeResponse, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if challenge.CanSkipSecondaryAuth {
		_, _ = fmt.Fprintln(h.output, "Tips: Add prefix '$' to skip secondary authentication")
	}
	input, err := h.readLine(challenge.Message)
	if err != nil {
		return CodeResponse{}, err
	}
	response := CodeResponse{Code: strings.TrimSpace(input)}
	if challenge.CanSkipSecondaryAuth {
		if code, found := strings.CutPrefix(response.Code, "$"); found {
			response.Code = strings.TrimSpace(code)
			response.SkipSecondaryAuth = true
		}
	}
	if response.Code == "" {
		return CodeResponse{}, fmt.Errorf("authentication code is empty")
	}
	return response, nil
}

func (h *CLIHandler) HandleTextCaptcha(challenge TextCaptchaChallenge) (TextCaptchaResponse, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if challenge.OutputPath == "" {
		return TextCaptchaResponse{}, fmt.Errorf("text captcha output path is empty")
	}
	if err := os.WriteFile(challenge.OutputPath, challenge.Image, 0644); err != nil {
		return TextCaptchaResponse{}, fmt.Errorf("write captcha image: %w", err)
	}
	code, err := h.readLine(challenge.Message)
	if err != nil {
		return TextCaptchaResponse{}, err
	}
	code = strings.TrimSpace(code)
	if code == "" {
		return TextCaptchaResponse{}, fmt.Errorf("captcha code is empty")
	}
	return TextCaptchaResponse{Code: code}, nil
}

func (h *CLIHandler) HandleClickCaptcha(challenge ClickCaptchaChallenge) (ClickCaptchaResponse, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if challenge.OutputPath == "" {
		return serveCaptchaInBrowser(challenge.Image, h.captchaTimeout, h.output)
	}
	if err := os.WriteFile(challenge.OutputPath, challenge.Image, 0644); err != nil {
		return ClickCaptchaResponse{}, fmt.Errorf("write captcha image: %w", err)
	}
	raw, err := h.readLine(challenge.Message)
	if err != nil {
		return ClickCaptchaResponse{}, err
	}
	return parseClickCaptchaResponse(raw)
}

func (h *CLIHandler) HandleExternalLogin(challenge ExternalLoginChallenge) (ExternalLoginResponse, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if challenge.LoginURL != "" {
		_, _ = fmt.Fprintf(h.output, "Visit %s to login, and catch the callback url\n", challenge.LoginURL)
	}
	callback, err := h.readLine(challenge.Message)
	if err != nil {
		return ExternalLoginResponse{}, err
	}
	callback = strings.TrimSpace(callback)
	if callback == "" {
		return ExternalLoginResponse{}, fmt.Errorf("callback URL is empty")
	}
	return ExternalLoginResponse{CallbackURL: callback}, nil
}

func (h *CLIHandler) readLine(message string) (string, error) {
	if message != "" {
		_, _ = fmt.Fprint(h.output, message)
		if !strings.HasSuffix(message, " ") {
			_, _ = fmt.Fprint(h.output, " ")
		}
	}
	line, err := h.input.ReadString('\n')
	if err != nil && !(err == io.EOF && len(line) > 0) {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func parseClickCaptchaResponse(raw string) (ClickCaptchaResponse, error) {
	var object struct {
		Coordinates [][]int `json:"coordinates"`
		Width       int     `json:"width"`
		Height      int     `json:"height"`
	}
	if json.Unmarshal([]byte(raw), &object) == nil && len(object.Coordinates) > 0 {
		response, err := pointsFromCoordinates(object.Coordinates)
		if err != nil {
			return ClickCaptchaResponse{}, err
		}
		response.Width = object.Width
		response.Height = object.Height
		return response, nil
	}

	var points []Point
	if json.Unmarshal([]byte(raw), &points) == nil && len(points) > 0 {
		return validatePoints(points)
	}

	var coordinates [][]int
	if json.Unmarshal([]byte(raw), &coordinates) == nil && len(coordinates) > 0 {
		return pointsFromCoordinates(coordinates)
	}
	return ClickCaptchaResponse{}, fmt.Errorf("unsupported click captcha response format")
}

func pointsFromCoordinates(coordinates [][]int) (ClickCaptchaResponse, error) {
	points := make([]Point, 0, len(coordinates))
	for _, coordinate := range coordinates {
		if len(coordinate) != 2 {
			return ClickCaptchaResponse{}, fmt.Errorf("invalid click captcha coordinate")
		}
		points = append(points, Point{X: coordinate[0], Y: coordinate[1]})
	}
	return validatePoints(points)
}

func validatePoints(points []Point) (ClickCaptchaResponse, error) {
	if len(points) == 0 {
		return ClickCaptchaResponse{}, fmt.Errorf("click captcha response is empty")
	}
	return ClickCaptchaResponse{Points: points}, nil
}

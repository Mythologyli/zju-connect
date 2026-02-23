package auth

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"time"

	"github.com/mythologyli/zju-connect/log"
)

const captchaPageHTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>zju-connect 验证码</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: #f0f2f5;
    display: flex;
    justify-content: center;
    align-items: center;
    min-height: 100vh;
  }
  .card {
    background: #fff;
    border-radius: 12px;
    box-shadow: 0 2px 12px rgba(0,0,0,0.1);
    padding: 32px;
    text-align: center;
  }
  h2 { color: #333; margin-bottom: 16px; font-size: 20px; }
  .hint { color: #666; font-size: 14px; margin-bottom: 12px; }
  .img-wrap {
    position: relative;
    display: inline-block;
    cursor: crosshair;
    user-select: none;
    margin-bottom: 16px;
  }
  .img-wrap img {
    display: block;
    /* no width/height constraints: render at natural pixel size */
  }
  .marker {
    position: absolute;
    width: 28px; height: 28px;
    border-radius: 50%;
    background: rgba(24,144,255,0.85);
    color: #fff;
    font-size: 14px; font-weight: bold;
    line-height: 28px; text-align: center;
    transform: translate(-50%, -50%);
    pointer-events: none;
    box-shadow: 0 1px 4px rgba(0,0,0,0.3);
  }
  .actions { margin-bottom: 16px; }
  .actions button {
    padding: 6px 18px;
    margin: 0 6px;
    border: 1px solid #d9d9d9;
    border-radius: 6px;
    background: #fff;
    color: #333;
    font-size: 14px;
    cursor: pointer;
    transition: all 0.2s;
  }
  .actions button:hover { border-color: #1890ff; color: #1890ff; }
  #submitBtn {
    width: 100%;
    padding: 10px;
    background: #1890ff;
    color: #fff;
    border: none;
    border-radius: 6px;
    font-size: 16px;
    cursor: pointer;
    transition: background 0.2s;
  }
  #submitBtn:hover { background: #40a9ff; }
  #submitBtn:disabled { background: #d9d9d9; cursor: not-allowed; }
  .status { margin-top: 12px; font-size: 14px; color: #888; }
  details.debug-panel { margin-top: 8px; text-align: left; }
  details.debug-panel > summary { cursor: pointer; color: #999; font-size: 12px; }
  .debug {
    margin-top: 6px; height: 100px; overflow-y: auto;
    font-size: 12px; color: #aaa; white-space: pre;
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  }
  .success { color: #52c41a; font-size: 18px; margin-top: 20px; display: none; }
</style>
</head>
<body>
<div class="card">
  <h2 id="headline">请按顺序点击图中指定的文字</h2>
  <p class="hint" id="hint">在验证码图片上依次点击对应文字的位置</p>
  <div class="img-wrap" id="imgWrap">
    <img id="captchaImg" src="/captcha.img" alt="验证码" draggable="false">
  </div>
  <div class="actions">
    <button id="undoBtn" type="button" onclick="undoClick()">撤销上一个</button>
    <button id="clearBtn" type="button" onclick="clearClicks()">全部清除</button>
  </div>
  <p class="status" id="status">已选择 0 个点</p>
  <details class="debug-panel" id="debugPanel">
    <summary id="debugSummary">Debug</summary>
    <pre class="debug" id="debug"></pre>
  </details>
  <button id="submitBtn" onclick="submitClicks()" disabled>提 交</button>
  <div class="success" id="success">提交成功，可以关闭此页面</div>
</div>
<script>
var clicks = [];
var imgWrap = document.getElementById('imgWrap');
var captchaImg = document.getElementById('captchaImg');
var statusEl = document.getElementById('status');
var submitBtn = document.getElementById('submitBtn');
var debugPanelEl = document.getElementById('debugPanel');
var debugSummaryEl = document.getElementById('debugSummary');
var debugEl = document.getElementById('debug');
var headlineEl = document.getElementById('headline');
var hintEl = document.getElementById('hint');
var undoBtnEl = document.getElementById('undoBtn');
var clearBtnEl = document.getElementById('clearBtn');
var successEl = document.getElementById('success');
var isSubmitting = false;

var I18N = {
  zh: {
    title: 'zju-connect 验证码',
    heading: '请按顺序点击图中指定的文字',
    hint: '在验证码图片上依次点击对应文字的位置',
    undo: '撤销上一个', clear: '全部清除',
    status: function(n) { return '已选择 ' + n + ' 个点'; },
    submit: '提 交', submitting: '提交中...',
    success: '提交成功，可以关闭此页面',
    submitFailed: '提交失败，请重试',
    networkError: '网络错误，请重试',
    imgAlt: '验证码',
    debugSummary: '调试信息'
  },
  en: {
    title: 'zju-connect Captcha',
    heading: 'Click the specified characters in order',
    hint: 'Click the matching characters on the captcha image in sequence.',
    undo: 'Undo', clear: 'Clear',
    status: function(n) { return 'Selected ' + n + ' point' + (n !== 1 ? 's' : ''); },
    submit: 'Submit', submitting: 'Submitting...',
    success: 'Submitted. You may close this page.',
    submitFailed: 'Submission failed. Please retry.',
    networkError: 'Network error. Please retry.',
    imgAlt: 'Captcha',
    debugSummary: 'Debug'
  }
};

var lang = (function() {
  var l = ((navigator.languages && navigator.languages[0]) || navigator.language || '').toLowerCase();
  return l.indexOf('zh') === 0 ? 'zh' : 'en';
})();

function tr(key) { return (I18N[lang] || I18N.en)[key]; }

function applyLang() {
  document.documentElement.lang = lang === 'zh' ? 'zh-CN' : 'en';
  document.title = tr('title');
  headlineEl.textContent = tr('heading');
  hintEl.textContent = tr('hint');
  undoBtnEl.textContent = tr('undo');
  clearBtnEl.textContent = tr('clear');
  captchaImg.alt = tr('imgAlt');
  debugSummaryEl.textContent = tr('debugSummary');
  successEl.textContent = tr('success');
  renderStatus();
}

function renderStatus() {
  statusEl.textContent = tr('status')(clicks.length);
  submitBtn.textContent = isSubmitting ? tr('submitting') : tr('submit');
  submitBtn.disabled = clicks.length === 0 || isSubmitting;
}

captchaImg.onload = function() { updateDebug(); };

captchaImg.addEventListener('click', function(e) {
  if (isSubmitting) return;
  var rect = captchaImg.getBoundingClientRect();
  var nw = captchaImg.naturalWidth || Math.round(rect.width);
  var nh = captchaImg.naturalHeight || Math.round(rect.height);
  var dw = rect.width || nw;
  var dh = rect.height || nh;

  var x = Math.max(0, Math.min(nw - 1, Math.round((e.clientX - rect.left) * nw / dw)));
  var y = Math.max(0, Math.min(nh - 1, Math.round((e.clientY - rect.top) * nh / dh)));

  clicks.push({x: x, y: y});
  renderMarkers();
  renderStatus();
  updateDebug();
});

function updateDebug() {
  var rect = captchaImg.getBoundingClientRect();
  var lines = ['natural: ' + captchaImg.naturalWidth + 'x' + captchaImg.naturalHeight
    + ', display: ' + Math.round(rect.width) + 'x' + Math.round(rect.height)
    + ', dpr: ' + window.devicePixelRatio];
  for (var i = 0; i < clicks.length; i++) {
    lines.push((i+1) + ': (' + clicks[i].x + ', ' + clicks[i].y + ')');
  }
  debugEl.textContent = lines.join('\n');
}

function renderMarkers() {
  var old = imgWrap.querySelectorAll('.marker');
  for (var i = 0; i < old.length; i++) old[i].remove();

  var rect = captchaImg.getBoundingClientRect();
  var nw = captchaImg.naturalWidth || Math.round(rect.width);
  var nh = captchaImg.naturalHeight || Math.round(rect.height);
  var dw = rect.width || nw;
  var dh = rect.height || nh;

  for (var i = 0; i < clicks.length; i++) {
    var m = document.createElement('div');
    m.className = 'marker';
    m.textContent = i + 1;
    m.style.left = (clicks[i].x * dw / nw) + 'px';
    m.style.top = (clicks[i].y * dh / nh) + 'px';
    imgWrap.appendChild(m);
  }
}

function undoClick() {
  if (isSubmitting) return;
  clicks.pop();
  renderMarkers();
  renderStatus();
  updateDebug();
}

function clearClicks() {
  if (isSubmitting) return;
  clicks = [];
  renderMarkers();
  renderStatus();
  updateDebug();
}

function submitClicks() {
  if (clicks.length === 0 || isSubmitting) return;
  var rect = captchaImg.getBoundingClientRect();
  var width = captchaImg.naturalWidth || Math.round(rect.width);
  var height = captchaImg.naturalHeight || Math.round(rect.height);
  var payload = JSON.stringify({
    coordinates: clicks.map(function(p) { return [p.x, p.y]; }),
    width: width, height: height
  });

  isSubmitting = true;
  renderStatus();

  var xhr = new XMLHttpRequest();
  xhr.open('POST', '/submit', true);
  xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
  xhr.onload = function() {
    if (xhr.status === 200) {
      imgWrap.style.display = 'none';
      document.querySelector('.actions').style.display = 'none';
      statusEl.style.display = 'none';
      submitBtn.style.display = 'none';
      debugPanelEl.style.display = 'none';
      successEl.style.display = 'block';
    } else {
      isSubmitting = false;
      renderStatus();
      alert(tr('submitFailed'));
    }
  };
  xhr.onerror = function() {
    isSubmitting = false;
    renderStatus();
    alert(tr('networkError'));
  };
  xhr.send('code=' + encodeURIComponent(payload));
  return false;
}

applyLang();
</script>
</body>
</html>`

// serveCaptchaInBrowser starts a temporary HTTP server to display the captcha
// image in the user's browser and waits for the user to click on character
// positions and submit the coordinates.
func serveCaptchaInBrowser(imgData []byte, timeout time.Duration) (string, error) {
	resultCh := make(chan string, 1)

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(captchaPageHTML))
	})

	mux.HandleFunc("/captcha.img", func(w http.ResponseWriter, r *http.Request) {
		contentType := http.DetectContentType(imgData)
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Write(imgData)
	})

	mux.HandleFunc("/submit", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		code := r.FormValue("code")
		if code == "" {
			http.Error(w, "empty code", http.StatusBadRequest)
			return
		}
		normalized, err := canonicalizeGraphCheckCode(code, imgData)
		if err != nil {
			http.Error(w, "invalid code: "+err.Error(), http.StatusBadRequest)
			return
		}
		select {
		case resultCh <- normalized:
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("ok"))
		default:
			http.Error(w, "already submitted", http.StatusConflict)
		}
	})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("failed to start captcha server: %w", err)
	}

	srv := &http.Server{Handler: mux}

	go srv.Serve(listener)

	addr := fmt.Sprintf("http://%s", listener.Addr().String())
	log.Printf("Captcha server started at %s", addr)

	openBrowser(addr)

	select {
	case code := <-resultCh:
		log.Println("Captcha code received from browser")
		srv.Shutdown(context.Background())
		return code, nil
	case <-time.After(timeout):
		srv.Shutdown(context.Background())
		return "", fmt.Errorf("captcha input timed out after %v", timeout)
	}
}

// openBrowser tries to open the given URL in the system's default browser.
func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "linux":
		cmd = exec.Command("xdg-open", url)
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", url)
	default:
		log.Printf("Unsupported platform for auto-opening browser, please visit: %s", url)
		return
	}
	if err := cmd.Start(); err != nil {
		log.Printf("Failed to open browser: %v. Please visit: %s", err, url)
	}
}

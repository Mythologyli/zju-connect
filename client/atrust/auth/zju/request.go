package zju

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/mythologyli/zju-connect/client/atrust/auth"
	"github.com/mythologyli/zju-connect/log"
	"io"
	"math/big"
	mathrand "math/rand"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strconv"
	"time"
)

const (
	BaseHost  = "vpn.zju.edu.cn"
	BaseURL   = "https://" + BaseHost
	UserAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) aTrustTray/2.4.10.50 Chrome/83.0.4103.94 Electron/9.0.2 Safari/537.36 aTrustTray-Linux-Plat-Ubuntu-x64 SPCClientType"
)

type Session struct {
	client   *http.Client
	username string
	password string
	deviceID string

	rid            string
	env            string
	csrfToken      string
	pubKey         string
	pubKeyExp      string
	antiReplayRand string
	ticket         string

	response map[string]json.RawMessage
}

func NewSession() *Session {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Transport: tr, Jar: jar, Timeout: 20 * time.Second}

	rid := base64.StdEncoding.EncodeToString([]byte(BaseHost))

	return &Session{
		client:   client,
		rid:      rid,
		response: make(map[string]json.RawMessage),
	}
}

func (s *Session) randSdpId(n ...int) string {
	length := 8
	if len(n) > 0 {
		length = n[0]
	}
	hexes := make([]byte, length)
	for i := 0; i < length; i++ {
		hexes[i] = "0123456789abcdef"[mathrand.Intn(16)]
	}
	return string(hexes)
}

func (s *Session) Login(username, password, deviceId, graphCodeFile string, cookies []auth.Cookie) (string, []auth.Cookie, error) {
	sid := ""
	if cookies != nil {
		for _, cookie := range cookies {
			if cookie.Host == BaseHost && cookie.Scheme == "https" && cookie.Name == "sid" {
				sid = cookie.Value
			}

			c := &http.Cookie{
				Name:  cookie.Name,
				Value: cookie.Value,
			}
			s.client.Jar.SetCookies(&url.URL{Host: cookie.Host, Scheme: cookie.Scheme}, []*http.Cookie{c})
		}
	}

	s.username = username
	s.password = password
	s.deviceID = deviceId
	s.env = base64.StdEncoding.EncodeToString([]byte(`{"deviceId":"` + deviceId + `"}`))

	isLogin, err := s.authConfig()
	if err != nil {
		return "", nil, err
	}
	if isLogin == 1 {
		log.Println("Already logged in")
		return sid, cookies, nil
	}

	graphCheckCodeEnable, err := s.psw("")
	if err != nil {
		return "", nil, err
	}

	if graphCheckCodeEnable == 1 {
		imgData, err := s.checkCode()
		if err != nil {
			return "", nil, err
		}

		if graphCodeFile != "" {
			err = os.WriteFile(graphCodeFile, imgData, 0644)
			if err != nil {
				return "", nil, fmt.Errorf("failed to write graph code image: %w", err)
			}
			log.Printf("Graph check code saved to %s", graphCodeFile)
		} else {
			log.Println("Graph check code required, but no file specified to save the image")
			return "", nil, fmt.Errorf("graph check code required, but no file specified to save the image")
		}

		isLogin, err = s.authConfig()
		if err != nil {
			return "", nil, err
		}

		graphCheckCode := ""
		log.Print("Please enter the graph check code JSON: ")
		_, err = fmt.Scanln(&graphCheckCode)
		if err != nil {
			return "", nil, err
		}

		graphCheckCodeEnable, err = s.psw(graphCheckCode)
		if err != nil {
			return "", nil, err
		}

		if graphCheckCodeEnable != 0 {
			log.Println("Graph check code still required after second login attempt")
			return "", nil, fmt.Errorf("graph check code still required after second login attempt")
		}
	}

	err = s.reportEnv()
	if err != nil {
		return "", nil, err
	}

	authID, err := s.authCheck()
	if err != nil {
		return "", nil, err
	}

	if authID != "" {
		err = s.sendSms(authID)
		if err != nil {
			return "", nil, err
		}
		err = s.smsCheckCode(authID)
		if err != nil {
			return "", nil, err
		}
	}

	err = s.onlineInfo()
	if err != nil {
		return "", nil, err
	}

	cookies = make([]auth.Cookie, 0)
	for _, cookie := range s.client.Jar.Cookies(&url.URL{Host: BaseHost, Scheme: "https"}) {
		if cookie.Name == "sid" {
			sid = cookie.Value
		}

		cookies = append(cookies, auth.Cookie{
			Host:   BaseHost,
			Scheme: "https",
			Name:   cookie.Name,
			Value:  cookie.Value,
		})
	}

	return sid, cookies, nil
}

func (s *Session) authConfig() (int, error) {
	log.Println("Perform GET /passport/v1/public/authConfig")

	u := BaseURL + "/passport/v1/public/authConfig"
	params := url.Values{
		"clientType": {"SDPClient"},
		"platform":   {"Linux"},
		"lang":       {"en-US"},
		"needTicket": {"1"},
	}
	req, _ := http.NewRequest("GET", u+"?"+params.Encode(), nil)
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("x-csrf-token", s.csrfToken)
	req.Header.Set("x-sdp-rid", s.rid)
	req.Header.Set("x-sdp-traceid", s.randSdpId())

	resp, err := s.client.Do(req)
	if err != nil {
		return 0, err
	}

	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)
	body, _ := io.ReadAll(resp.Body)

	var re struct {
		Data struct {
			IsLogin        int    `json:"isLogin"`
			CSRF           string `json:"csrfToken"`
			PubKey         string `json:"pubKey"`
			PubKeyExp      string `json:"pubKeyExp"`
			AntiReplayRand string `json:"antiReplayRand"`
		} `json:"data"`
	}
	err = json.Unmarshal(body, &re)
	if err != nil {
		return 0, err
	}

	s.csrfToken = re.Data.CSRF
	s.pubKey = re.Data.PubKey
	s.pubKeyExp = re.Data.PubKeyExp
	s.antiReplayRand = re.Data.AntiReplayRand

	return re.Data.IsLogin, nil
}

func (s *Session) psw(graphCheckCode string) (int, error) {
	log.Println("Perform POST /passport/v1/auth/psw")

	N := new(big.Int)
	N.SetString(s.pubKey, 16)
	E, _ := strconv.Atoi(s.pubKeyExp)
	pub := &rsa.PublicKey{N: N, E: E}

	msg := []byte(s.password + "_" + s.antiReplayRand)
	cipherBytes, err := rsa.EncryptPKCS1v15(rand.Reader, pub, msg)
	if err != nil {
		return 0, err
	}
	encryptedPwd := hex.EncodeToString(cipherBytes)

	data := map[string]interface{}{
		"username":    s.username + "@Radius",
		"password":    encryptedPwd,
		"rememberPwd": "0",
	}

	if graphCheckCode != "" {
		data["graphCheckCode"] = graphCheckCode
	}
	postBody, _ := json.Marshal(data)

	u := BaseURL + "/passport/v1/auth/psw"
	params := url.Values{
		"clientType": {"SDPClient"},
		"platform":   {"Linux"},
		"lang":       {"en-US"},
	}
	req, _ := http.NewRequest("POST", u+"?"+params.Encode(), bytes.NewReader(postBody))
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Content-Type", "application/json;charset=utf-8")
	req.Header.Set("x-csrf-token", s.csrfToken)
	req.Header.Set("x-sdp-env", s.env)
	req.Header.Set("x-sdp-traceid", s.randSdpId())

	resp, err := s.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)
	body, _ := io.ReadAll(resp.Body)

	var re struct {
		Data struct {
			Ticket               string `json:"ticket"`
			GraphCheckCodeEnable int    `json:"graphCheckCodeEnable"`
		} `json:"data"`
	}
	err = json.Unmarshal(body, &re)
	if err != nil {
		return 0, err
	}

	s.ticket = re.Data.Ticket

	return re.Data.GraphCheckCodeEnable, nil
}

func (s *Session) checkCode() ([]byte, error) {
	log.Println("Perform GET /passport/v1/public/checkCode")

	u := BaseURL + "/passport/v1/public/checkCode"
	params := url.Values{
		"clientType": {"SDPClient"},
		"platform":   {"Linux"},
		"lang":       {"en-US"},
		"rnd":        {strconv.FormatInt(time.Now().UnixMilli(), 10)},
	}
	req, _ := http.NewRequest("GET", u+"?"+params.Encode(), nil)
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept", "image/webp,image/apng,image/*,*/*;q=0.8")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)
	body, _ := io.ReadAll(resp.Body)

	return body, nil
}

func (s *Session) reportEnv() error {
	log.Println("Perform POST /controller/v1/public/reportEnv")

	u := BaseURL + "/controller/v1/public/reportEnv"
	params := url.Values{
		"clientType": {"SDPClient"},
		"platform":   {"Linux"},
		"lang":       {"en-US"},
	}

	if s.ticket == "" {
		return fmt.Errorf("ticket is empty")
	}

	payload := map[string]interface{}{
		"ticket":   s.ticket,
		"deviceId": s.deviceID,
		"env": map[string]interface{}{
			"endpoint": map[string]interface{}{
				"device_id": s.deviceID,
				"device": map[string]interface{}{
					"type": "browser",
				},
			},
		},
	}
	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", u+"?"+params.Encode(), bytes.NewReader(body))
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Content-Type", "application/json;charset=utf-8")
	req.Header.Set("x-csrf-token", s.csrfToken)
	req.Header.Set("x-sdp-traceid", s.randSdpId())

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)
	body, _ = io.ReadAll(resp.Body)

	var re struct {
		Code int `json:"code"`
	}

	err = json.Unmarshal(body, &re)
	if err != nil {
		return err
	}

	if re.Code != 0 {
		log.Printf("reportEnv failed with code %d: %s", re.Code, string(body))
		return fmt.Errorf("reportEnv failed with code %d", re.Code)
	}

	return nil
}

func (s *Session) authCheck() (string, error) {
	log.Println("Perform GET /passport/v1/auth/authCheck")

	u := BaseURL + "/passport/v1/auth/authCheck"
	params := url.Values{
		"clientType": {"SDPClient"},
		"platform":   {"Linux"},
		"lang":       {"en-US"},
	}
	req, _ := http.NewRequest("GET", u+"?"+params.Encode(), nil)
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("x-csrf-token", s.csrfToken)
	req.Header.Set("x-sdp-traceid", s.randSdpId())

	resp, err := s.client.Do(req)
	if err != nil {
		return "", err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)
	body, _ := io.ReadAll(resp.Body)

	var ac struct {
		Data struct {
			NextServiceList []struct {
				AuthId string `json:"authId"`
			} `json:"nextServiceList"`
		} `json:"data"`
	}
	err = json.Unmarshal(body, &ac)
	if err != nil {
		return "", err
	}

	if len(ac.Data.NextServiceList) > 0 {
		return ac.Data.NextServiceList[0].AuthId, nil
	} else {
		return "", nil
	}
}

func (s *Session) sendSms(authId string) error {
	log.Println("Perform GET /passport/v1/auth/sms")
	u := BaseURL + "/passport/v1/auth/sms"
	params := url.Values{
		"action":       {"sendsms"},
		"clientType":   {"SDPClient"},
		"platform":     {"Linux"},
		"lang":         {"en-US"},
		"isPrevEffect": {"0"},
		"taskId":       {""},
		"authId":       {authId},
	}
	req, _ := http.NewRequest("GET", u+"?"+params.Encode(), nil)
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("x-csrf-token", s.csrfToken)
	req.Header.Set("x-sdp-traceid", s.randSdpId())

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)
	body, _ := io.ReadAll(resp.Body)

	var re struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    struct {
			Tips string `json:"tips"`
		}
	}
	err = json.Unmarshal(body, &re)
	if err != nil {
		return err
	}

	if re.Code != 0 {
		log.Printf("sendSms failed with code %d: %s", re.Code, re.Message)
		return fmt.Errorf("sendSms failed with code %d: %s", re.Code, re.Message)
	}

	log.Printf("%s: %s", re.Message, re.Data.Tips)

	return nil
}

func (s *Session) smsCheckCode(authId string) error {
	log.Println("Perform POST /passport/v1/auth/sms")

	code := ""
	log.Print("Please enter the SMS verification code: ")
	_, err := fmt.Scanln(&code)
	if err != nil {
		return err
	}

	u := BaseURL + "/passport/v1/auth/sms"
	params := url.Values{
		"action":     {"checkcode"},
		"clientType": {"SDPClient"},
		"platform":   {"Linux"},
		"lang":       {"en-US"},
	}
	payload := map[string]interface{}{
		"isPrevEffect":      false,
		"code":              code,
		"skipSecondaryAuth": "0",
		"taskId":            "",
		"authId":            authId,
	}
	bdy, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", u+"?"+params.Encode(), bytes.NewReader(bdy))
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Content-Type", "application/json;charset=utf-8")
	req.Header.Set("x-csrf-token", s.csrfToken)
	req.Header.Set("x-sdp-traceid", s.randSdpId())

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)
	body, _ := io.ReadAll(resp.Body)

	var re struct {
		Code int `json:"code"`
	}
	err = json.Unmarshal(body, &re)
	if err != nil {
		return err
	}

	if re.Code != 0 {
		log.Printf("smsCheckCode failed with code %d: %s", re.Code, string(body))
		return fmt.Errorf("smsCheckCode failed with code %d", re.Code)
	}

	return nil
}

func (s *Session) onlineInfo() error {
	log.Println("Perform GET /passport/v1/user/onlineInfo")

	u := BaseURL + "/passport/v1/user/onlineInfo"
	params := url.Values{
		"clientType": {"SDPClient"},
		"platform":   {"Linux"},
		"lang":       {"en-US"},
	}
	req, _ := http.NewRequest("GET", u+"?"+params.Encode(), nil)
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("x-csrf-token", s.csrfToken)
	req.Header.Set("x-sdp-traceid", s.randSdpId())

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)
	body, _ := io.ReadAll(resp.Body)

	var re struct {
		Code int `json:"code"`
	}

	err = json.Unmarshal(body, &re)
	if err != nil {
		return err
	}

	if re.Code != 0 {
		log.Printf("onlineInfo failed with code %d: %s", re.Code, string(body))
		return fmt.Errorf("onlineInfo failed with code %d", re.Code)
	}

	return nil
}

func (s *Session) ClientResource() ([]byte, error) {
	log.Println("Perform POST /controller/v1/user/clientResource")

	u := BaseURL + "/controller/v1/user/clientResource"
	params := url.Values{
		"clientType": {"SDPClient"},
		"platform":   {"Linux"},
		"lang":       {"en-US"},
	}
	payload := map[string]interface{}{
		"resourceType": map[string]interface{}{
			"sdpPolicy":       struct{}{},
			"appList":         struct{}{},
			"favoriteAppList": struct{}{},
			"featureCenter":   struct{}{},
			"uemSpace": map[string]interface{}{
				"params": map[string]string{"action": "login"},
			},
		},
	}
	bdy, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", u+"?"+params.Encode(), bytes.NewReader(bdy))
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Content-Type", "application/json;charset=utf-8")
	req.Header.Set("x-csrf-token", s.csrfToken)
	req.Header.Set("x-sdp-traceid", s.randSdpId())

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)
	body, _ := io.ReadAll(resp.Body)

	return body, nil
}

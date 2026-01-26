package auth

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/mythologyli/zju-connect/log"
)

func (s *Session) loginAuthPsw(username, password, loginDomain, graphCodeFile string) error {
	graphCheckCodeEnable, err := s.pswImpl(username, password, loginDomain, "")
	if err != nil {
		return err
	}

	if graphCheckCodeEnable == 1 {
		imgData, err := s.checkCode()
		if err != nil {
			return err
		}

		if graphCodeFile != "" {
			err = os.WriteFile(graphCodeFile, imgData, 0644)
			if err != nil {
				return fmt.Errorf("failed to write graph code image: %w", err)
			}
			log.Printf("Graph check code saved to %s", graphCodeFile)
		} else {
			log.Println("Graph check code required, but no file specified to save the image")
			return fmt.Errorf("graph check code required, but no file specified to save the image")
		}

		_, _, err = s.authConfigInit()
		if err != nil {
			return err
		}

		graphCheckCode := ""
		log.Print("Please enter the graph check code JSON: ")
		_, err = fmt.Scanln(&graphCheckCode)
		if err != nil {
			return err
		}

		graphCheckCodeEnable, err = s.pswImpl(username, password, loginDomain, graphCheckCode)
		if err != nil {
			return err
		}

		if graphCheckCodeEnable != 0 {
			log.Println("Graph check code still required after second login attempt")
			return fmt.Errorf("graph check code still required after second login attempt")
		}
	}
	return nil
}

func (s *Session) pswImpl(username, password, loginDomain, graphCheckCode string) (int, error) {
	log.Println("Perform POST /passport/v1/auth/psw")

	N := new(big.Int)
	N.SetString(s.pubKey, 16)
	E, _ := strconv.Atoi(s.pubKeyExp)
	pub := &rsa.PublicKey{N: N, E: E}

	msg := []byte(password + "_" + s.antiReplayRand)
	cipherBytes, err := rsa.EncryptPKCS1v15(rand.Reader, pub, msg)
	if err != nil {
		return 0, err
	}
	encryptedPwd := hex.EncodeToString(cipherBytes)

	data := map[string]interface{}{
		"username":    username + "@" + loginDomain,
		"password":    encryptedPwd,
		"rememberPwd": "0",
	}

	if graphCheckCode != "" {
		data["graphCheckCode"] = graphCheckCode
	}
	postBody, _ := json.Marshal(data)

	u := s.baseURL + "/passport/v1/auth/psw"
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
	log.DebugPrintf("Received psw: %s", string(body))

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
	log.DebugPrintf("Parsed psw: %+v", re)

	s.ticket = re.Data.Ticket

	return re.Data.GraphCheckCodeEnable, nil
}

func (s *Session) checkCode() ([]byte, error) {
	log.Println("Perform GET /passport/v1/public/checkCode")

	u := s.baseURL + "/passport/v1/public/checkCode"
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
	log.DebugPrintf("Received check code image: %d bytes", len(body))

	return body, nil
}

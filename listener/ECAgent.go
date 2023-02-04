package listener

import (
	"ZJUConnect/core"
	"ZJUConnect/core/config"
	"ZJUConnect/parser"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"os/exec"
	REGEXP "regexp"
	"runtime"
	"strconv"
	"time"

	"encoding/hex"

	"fmt"
	"strings"

	"log"
	"net/http"
)

type Env_ struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	regexp     *REGEXP.Regexp
}

type ECAgentResult_ struct {
	server string
	port   string
	twfID  string
}

var Env Env_
var ECAgentResult ECAgentResult_
var ECAgentPort int

/** This is a quick implementation of ECAgent listener protocol
 */

func HelloServer(w http.ResponseWriter, req *http.Request) {
	reqMap := make(map[string]string)
	log.Printf("Simple ECAgent #> ClientRequest: %s \n", req.RequestURI)

	if req.RequestURI == "/ECAgent/" {
		_, err := w.Write([]byte("Init ECAgent env successfully. You can login to vpn now."))
		if err != nil {
			panic(err)
		}
		return
	}

	constructRespon := func(operate, result, message, debug string) string {
		return "(\"{\\\"type\\\":\\\"" + operate + "\\\",\\\"result\\\":\\\"" + result + "\\\",\\\"message\\\":\\\"" + message + "\\\",\\\"debug\\\":\\\"" + debug + "\\\"}\");"
	}

	form := Env.regexp.FindAllString(req.RequestURI, -1)

	for _, ent := range form {
		entry := strings.Split(ent, "=")
		reqMap[entry[0]] = entry[1]

		if core.DebugDump {
			fmt.Printf("request > %s\n", ent)
		}
	}

	response := strings.Builder{}

	action := reqMap["op"]
	//token := reqMap["token"]
	//Guid := reqMap["Guid"]
	callback := reqMap["callback"]

	response.WriteString(callback)

	//TODO:: Optimize & reformat
	switch {
	case action == "InitECAgent":
		response.WriteString(constructRespon(action, "1", "", "CSCM_EXIST, init ok"))
		break
	case action == "GetEncryptKey":
		//https://github.com/creationix/jsbn/blob/master/README.md

		modulus := fmt.Sprintf("%02X", Env.publicKey.N)
		response.WriteString(constructRespon(action, modulus, "", "CSCM_EXIST, init ok"))
		break
	case action == "DoConfigure":
		/*
		   op=DoConfigure
		   arg1=
		   token= hex_md5(session + '__md5_salt_for_ecagent_session__')
		   Guid=
		   callback=EA_cbxxxxx
		*/
		arg1 := reqMap["arg1"]

		Configure := strings.Split(arg1, "%20")

		switch Configure[0] {
		case "SET":
			switch Configure[1] {
			case "SERVADDR":
				server := Configure[2]
				port := Configure[3]

				ECAgentResult.server = server
				ECAgentResult.port = port

				log.Printf("server: %s port: %s\n", server, port)

				break
			case "TWFID":
				EncryptedTwfIDHex := Configure[2]

				EncryptedTwfID, err := hex.DecodeString(EncryptedTwfIDHex)
				if err != nil {
					fmt.Println(err)
				}

				DecryptedTwfid, err := rsa.DecryptPKCS1v15(rand.Reader, Env.privateKey, EncryptedTwfID)
				if err != nil {
					fmt.Println(err)
				}

				if ECAgentResult.twfID == "" {
					ECAgentResult.twfID = string(DecryptedTwfid[:])

					log.Printf("Encrypted twfid: %s \n", EncryptedTwfIDHex)
					log.Printf("Decrypted twfid: %s \n", ECAgentResult.twfID)

					go startClient(ECAgentResult)
				}
				break
			}
		}

		response.WriteString(constructRespon(action, "1", "", ""))
		break
	case action == "CheckProxySetting":
		response.WriteString(constructRespon(action, "-1", "", ""))
		break
	case action == "TestProxyServer":
		response.WriteString(constructRespon(action, "-1", "", ""))
		break
	case action == "GetConfig":
		//op=GetConfig&arg1=1&token=&Guid=&callback=EA_cbxxxxx

		if reqMap["arg1"] == "1" {
			conf := config.Conf{}
			_, ok := parser.ParseXml(&conf, ECAgentResult.server, config.PathConf, ECAgentResult.twfID)

			confWeb := config.ConfWeb{Conf: conf}

			if ok {
				result, err := json.Marshal(confWeb)
				if err != nil {
					fmt.Println("Cannot convert Json.", err)
					return
				}

				replacementMap := map[string]string{}

				sh1t := strings.ReplaceAll(strings.ReplaceAll(string(result), "\\", "\\\\"), "\"", "\\\"")

				for from, to := range replacementMap {
					sh1t = strings.ReplaceAll(sh1t, from, to)
				}

				response.WriteString("(\"" + sh1t + "\");")
			} else {
				response.WriteString("(\"" + "\");")
			}
		} else if reqMap["arg1"] == "2" {
			res := config.Resource{}
			_, ok := parser.ParseXml(&res, ECAgentResult.server, config.PathRlist, ECAgentResult.twfID)

			ResourceList := config.ResourceWeb{Resource: res}

			if ok {
				result, err := json.Marshal(ResourceList)
				if err != nil {
					fmt.Println("Cannot convert Json.", err)
					return
				}

				replacementMap := map[string]string{
					"ID":             "id",
					"Name":           "name",
					"Type":           "type",
					"Proto":          "proto",
					"Svc":            "svc",
					"Host":           "host",
					"Port":           "port",
					"EnableDisguise": "enable_disguise",
					"Note":           "note",
					"Attr":           "attr",
					"AppPath":        "app_path",
					"RcGrpID":        "rc_grp_id",
					"RcLogo":         "rc_logo",
					"Authorization":  "authorization",
					"AuthSpID":       "auth_sp_id",
					"Selectid":       "selectid",
				}

				sh1t := strings.ReplaceAll(strings.ReplaceAll(string(result), "\\", "\\\\"), "\"", "\\\"")

				for from, to := range replacementMap {
					sh1t = strings.ReplaceAll(sh1t, from, to)
				}

				response.WriteString("(\"" + sh1t + "\");")
			} else {
				response.WriteString("(\"" + "\");")
			}
		}
		break
	case action == "CheckReLogin":
		response.WriteString(constructRespon(action, "1", "", ""))
		break
	case action == "UpdateControls":
		response.WriteString(constructRespon(action, "1", "", ""))
		break
	case action == "DoQueryService":
		//TODO:: handle diff types
		response.WriteString(constructRespon(action, "26", "", ""))
		break
	case action == "StartService":
		response.WriteString(constructRespon(action, "1", "", ""))
		break
	case action == "doXmlConfigure":
		response.WriteString(constructRespon(action, "1", "", ""))
		break
	case action == "__check_alive__":
		response.Reset()
		response.WriteString("e(\"1\");")
		break
	default:
		log.Printf("Unknown action %s\n", action)
	}

	w.Header().Set("Content-Type", "text/javascript; charset=UTF-8")

	if core.DebugDump {
		fmt.Printf("response > %s \n", response.String())
	}

	_, err := w.Write([]byte(response.String()))
	if err != nil {
		return
	}
}

func startClient(config ECAgentResult_) {
	port, err := strconv.Atoi(config.port)
	if err != nil {
		log.Fatal("Cannot parse port!")
	}

	log.Printf("Starting Client ..... \n")

	core.StartClient(config.server, port, "", "", config.twfID)
}

/*
*
generate Pkcs1 keys (to decrypt the twfID from javascript's request)
*/
func generateKey() {
	var err error
	// generate private key
	Env.privateKey, err = rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		log.Fatal("Failed generating private key")
	}

	go Env.privateKey.Precompute()
	// validate private key
	err = Env.privateKey.Validate()
	if err != nil {
		log.Fatal("Failed validating private key")
	}

	Env.publicKey = &Env.privateKey.PublicKey
}

func initRegExp() {
	var err error
	Env.regexp, err = REGEXP.Compile("[a-zA-Z0-9]*=[a-zA-Z0-9_.%]*")

	if err != nil {
		log.Fatal(err)
		return
	}
}

/*
*
Create the cert which server uses
*/
func generateServerCert() (string, string) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		log.Fatal(err)
	}

	x509temple := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.UnixMilli(0),
		NotAfter:     time.Now().Add(time.Hour * 24 * 365),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,

		IsCA:        true,
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	cert, err := x509.CreateCertificate(rand.Reader, &x509temple, &x509temple, &privateKey.PublicKey, privateKey)
	if err != nil {
		panic(err)
	}

	buffer := &bytes.Buffer{}
	err = pem.Encode(buffer, &pem.Block{Type: "CERTIFICATE", Bytes: cert})
	if err != nil {
		panic(err)
	}
	certStr := buffer.String()
	buffer.Reset()

	certPrivKey := x509.MarshalPKCS1PrivateKey(privateKey)

	err = pem.Encode(buffer, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: certPrivKey})
	if err != nil {
		panic(err)
	}
	key := buffer.String()

	return certStr, key
}

// TODO:: Move to utils\FileUtils.go
func createTempFile(fileNamePattern, data string) *os.File {
	f, err := os.CreateTemp("", fileNamePattern)
	if err != nil {
		log.Fatal(err)
	}

	defer func(f *os.File) {
		err := f.Close()
		if err != nil {
			panic(err)
		}
	}(f)

	_, err = f.Write([]byte(data))
	if err != nil {
		panic(err)
	}

	return f
}

func checkPort() {
	ECAgentPort = 54530
	Ports := []int{54530, 54541, 54552, 54563, 54574, 54585, 54596, 54607}
	/* available ports: 54530, 54541, 54552, 54563, 54574, 54585, 54596, 54607
	 */

	log.Printf("Checking available port...")

	for index, port := range Ports {
		ln, err := net.Listen("tcp", fmt.Sprintf(":%v", port))
		ln.Close()

		if err == nil {
			ECAgentPort = port
			break
		}

		if index == 7 {
			log.Fatal("Cannot find available port!")
		}
	}
}

func StartECAgent() {
	Env = Env_{}
	ECAgentResult = ECAgentResult_{}

	checkPort()
	initRegExp()
	generateKey()

	cert, key := generateServerCert()
	certFile := createTempFile("ECAgent-*.crt", cert)
	keyFile := createTempFile("ECAgent-*.key", key)

	go func() {
		<-time.After(500 * time.Millisecond)
		url := fmt.Sprintf("https://127.0.0.1:%v/ECAgent/", ECAgentPort)

		switch runtime.GOOS {
		case "windows":
			err := exec.Command("cmd", "/c", "start", url).Run()
			if err != nil {
				panic(err)
			}
		case "darwin":
			err := exec.Command("open", url).Run()
			if err != nil {
				panic(err)
			}
		default:
			err := exec.Command("xdg-open", url).Run()
			if err != nil {
				panic(err)
			}
		}
	}()

	log.Printf(fmt.Sprintf("ECAgent is Listening on %v. (EXPERIMENT)\n", ECAgentPort))

	//TODO:: Handle port in use error
	http.HandleFunc("/ECAgent/", HelloServer)
	if err := http.ListenAndServeTLS(fmt.Sprintf(":%v", ECAgentPort), certFile.Name(), keyFile.Name(), nil); err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}

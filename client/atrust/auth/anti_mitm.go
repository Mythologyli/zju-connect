package auth

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

const (
	sangforCertificateDigestSuffix = "@~*&!()-"
	sangforChallengeSalt           = "OrHWuJz7gku5awmVb5w1sKTmfeCWHmzokBxmn0sn0faIcv1G10PdrbbRGKBrrZ3m"
	sangforSignatureSalt           = "3uW5IEy8KwDaOMK8uw1TmNr50U3aK1Qdu8b6vopXxGstzan3AJXxVNR6piuKi5Nq"
)

type antiMITMAttackData struct {
	Enable             int    `json:"enable"`
	DevicePubKeyMod    string `json:"devicePubKeyMod"`
	DevicePubKeyExp    string `json:"devicePubKeyExp"`
	RSACert            string `json:"rsaCert"`
	SM2EncCert         string `json:"sm2encCert"`
	Challenge          string `json:"challenge"`
	EncryptedChallenge string `json:"encryptedChallenge"`
	Ticket             string `json:"ticket"`
	AntiMITMRequest    bool   `json:"antiMITMRequest"`
	MITMSignature      string `json:"mitmSig"`
	raw                []byte
}

func (data *antiMITMAttackData) UnmarshalJSON(raw []byte) error {
	type plain antiMITMAttackData
	if err := json.Unmarshal(raw, (*plain)(data)); err != nil {
		return err
	}
	data.raw = append(data.raw[:0], raw...)
	return nil
}

// sangforCertificateDigest reproduces the SDK's certificate identifier:
// SHA-256(base64(DER) + "@~*&!()-"), formatted as uppercase hexadecimal.
func sangforCertificateDigest(rawDER []byte) []byte {
	encoded := base64.StdEncoding.EncodeToString(rawDER)
	return sangforEncodedCertificateDigest(encoded)
}

func sangforEncodedCertificateDigest(encoded string) []byte {
	digest := sha256.Sum256([]byte(encoded + sangforCertificateDigestSuffix))
	return digest[:]
}

func verifySangforChallenge(data antiMITMAttackData) error {
	if data.DevicePubKeyMod == "" || data.DevicePubKeyExp == "" || data.Challenge == "" || data.EncryptedChallenge == "" {
		return fmt.Errorf("aTrust anti-MITM challenge verification failed: incomplete server data")
	}

	material := sha256.Sum256([]byte(data.DevicePubKeyMod + data.DevicePubKeyExp + sangforChallengeSalt))
	block, err := aes.NewCipher(material[:aes.BlockSize])
	if err != nil {
		return fmt.Errorf("aTrust anti-MITM challenge verification failed: %w", err)
	}
	plainText := pkcs7Pad([]byte(data.Challenge), aes.BlockSize)
	cipherText := make([]byte, len(plainText))
	cipher.NewCBCEncrypter(block, material[aes.BlockSize:]).CryptBlocks(cipherText, plainText)
	actual := strings.ToUpper(hex.EncodeToString(cipherText))

	if subtle.ConstantTimeCompare([]byte(actual), []byte(data.EncryptedChallenge)) != 1 {
		return fmt.Errorf("aTrust anti-MITM challenge mismatch")
	}
	return nil
}

func verifySangforMITMSignature(data antiMITMAttackData) error {
	if data.MITMSignature == "" || len(data.raw) == 0 {
		return fmt.Errorf("aTrust anti-MITM signature verification failed: incomplete server data")
	}
	actual, err := sangforMITMSignature(data)
	if err != nil {
		return fmt.Errorf("aTrust anti-MITM signature verification failed: %w", err)
	}
	expected := strings.ToUpper(data.MITMSignature)
	if subtle.ConstantTimeCompare([]byte(actual), []byte(expected)) != 1 {
		return fmt.Errorf("aTrust anti-MITM signature mismatch")
	}
	return nil
}

func sangforMITMSignature(data antiMITMAttackData) (string, error) {
	key := sangforSignatureKey(data)

	origin, err := sangforOriginSignatureData(data.raw)
	if err != nil {
		return "", err
	}
	return sangforHMAC(key, []byte(origin)), nil
}

func sangforSignatureKey(data antiMITMAttackData) []byte {
	first := sha256.Sum256([]byte(data.DevicePubKeyMod + data.DevicePubKeyExp + sangforSignatureSalt))
	secondInput := strings.ToUpper(hex.EncodeToString(first[:])) + data.Challenge
	second := sha256.Sum256([]byte(secondInput))
	key := make([]byte, sha256.Size)
	for i := range key {
		key[i] = first[i] ^ second[i]
	}
	return key
}

func sangforHMAC(key, message []byte) string {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(message)
	return strings.ToUpper(hex.EncodeToString(mac.Sum(nil)))
}

func sangforNonce() (string, error) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return strings.ToUpper(hex.EncodeToString(nonce)), nil
}

func sangforOriginSignatureData(raw []byte) (string, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return "", err
	}

	fields := make(map[string]string)
	collectSangforSignatureFields(value, fields)
	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+":"+fields[key])
	}
	return strings.Join(parts, "&"), nil
}

func collectSangforSignatureFields(value any, fields map[string]string) {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if key == "mitmSig" {
				continue
			}
			switch child.(type) {
			case map[string]any, []any:
				collectSangforSignatureFields(child, fields)
			default:
				fields[key] = sangforScalarString(child)
			}
		}
	case []any:
		for _, child := range typed {
			collectSangforSignatureFields(child, fields)
		}
	}
}

func sangforScalarString(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case bool:
		return strconv.FormatBool(typed)
	case json.Number:
		return typed.String()
	case nil:
		return "null"
	default:
		return fmt.Sprint(typed)
	}
}

func pkcs7Pad(plainText []byte, blockSize int) []byte {
	paddingLength := blockSize - len(plainText)%blockSize
	padded := make([]byte, len(plainText)+paddingLength)
	copy(padded, plainText)
	for i := len(plainText); i < len(padded); i++ {
		padded[i] = byte(paddingLength)
	}
	return padded
}

// verifySangforCertificateIdentity reproduces checkCertIdentical, the final
// certificate-identity stage of the SDK's larger anti-MITM protocol.
func verifySangforCertificateIdentity(peerCertificates []*x509.Certificate, data antiMITMAttackData) error {
	if data.Enable != 1 {
		return nil
	}
	if len(peerCertificates) == 0 {
		return fmt.Errorf("aTrust anti-MITM verification failed: TLS peer did not provide a certificate")
	}

	expected := antiMITMCertificateDigests(data)
	if len(expected) == 0 {
		return fmt.Errorf("aTrust anti-MITM verification failed: server enabled verification without a certificate")
	}
	for _, certificate := range peerCertificates {
		actual := sangforCertificateDigest(certificate.Raw)
		for _, candidate := range expected {
			if subtle.ConstantTimeCompare(actual, candidate) == 1 {
				return nil
			}
		}
	}

	actual := sangforCertificateDigest(peerCertificates[0].Raw)
	return fmt.Errorf("aTrust anti-MITM certificate mismatch: got %s", strings.ToUpper(hex.EncodeToString(actual)))
}

func antiMITMCertificateDigests(data antiMITMAttackData) [][]byte {
	encodedCertificates := []string{data.RSACert, data.SM2EncCert}
	digests := make([][]byte, 0, len(encodedCertificates))
	for _, encoded := range encodedCertificates {
		if encoded == "" {
			continue
		}
		digests = append(digests, sangforEncodedCertificateDigest(encoded))
	}
	return digests
}

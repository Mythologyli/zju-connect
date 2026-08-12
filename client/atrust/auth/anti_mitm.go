package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

const sangforCertificateDigestSuffix = "@~*&!()-"

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

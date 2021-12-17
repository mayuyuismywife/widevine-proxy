package widevineproxy

import (
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
)

// LicenseAuthority to manage the key and license business logic.
type LicenseAuthority interface {
	BuildLicenseMessage(reqBody []byte, psshData *PsshData) (*Message, error)
	GetLicenseServerURL() string
	GetSigningKey() []byte
	GetSigningIV() []byte
	GetProvider() string
}

// Proxy structure.
type Proxy struct {
	LicenseAuthority LicenseAuthority
	httpCaller       *http.Client
	Logger           *logrus.Logger
}

// NewWidevineProxy creates an instance for grant widevine license with Widevine Cloud-based services.
func NewWidevineProxy(la LicenseAuthority, logger *logrus.Logger) *Proxy {
	client := &http.Client{
		Timeout: time.Second * 10,
		Transport: &http.Transport{
			Dial: (&net.Dialer{
				Timeout: 5 * time.Second,
			}).Dial,
			TLSHandshakeTimeout: 5 * time.Second,
		},
	}

	return &Proxy{
		LicenseAuthority: la,
		Logger:           logger,
		httpCaller:       client,
	}
}

// GetLicense is to create the certification to client if body size less than 50 or create license request for license.
func (wp *Proxy) GetLicense(body []byte) (*LicenseResponse, error) {
	if len(body) < 50 {
		req, err := wp.buildCertificateRequest(body)
		if err != nil {
			return nil, err
		}
		response, err := wp.sendReqeust(req)
		if err != nil {
			return nil, err
		}
		wp.Logger.WithFields(
			logrus.Fields{
				"status":           response.Status,
				"message_type":     response.MessageType,
				"license_metadata": response.LicenseMetadata,
				"supported_tracks": response.SupportedTracks,
				"model":            response.Model,
				"security_level":   response.SecurityLevel,
				"session_state":    response.SessionState,
				"platform":         response.Platform,
				"client_info":      response.ClientInfo,
			}).Info("Certification Request Success.")
		return response, nil
	}

	// Parse License
	parseLicenseReq, err := wp.parseLicense(body)
	if err != nil {
		return nil, err
	}
	rawMessage, err := wp.sendReqeust(parseLicenseReq)
	if err != nil {
		return nil, err
	}
	wp.Logger.WithFields(
		logrus.Fields{
			"status":           rawMessage.Status,
			"message_type":     rawMessage.MessageType,
			"license_metadata": rawMessage.LicenseMetadata,
			"supported_tracks": rawMessage.SupportedTracks,
			"model":            rawMessage.Model,
			"security_level":   rawMessage.SecurityLevel,
			"session_state":    rawMessage.SessionState,
			"platform":         rawMessage.Platform,
			"client_info":      rawMessage.ClientInfo,
		}).Info("License Parse Success.")

	// Create Build License
	req, err := wp.buildLicenseRequest(body, &rawMessage.PsshData)
	if err != nil {
		return nil, err
	}
	response, err := wp.sendReqeust(req)
	if err != nil {
		return nil, err
	}
	logger := wp.Logger.WithFields(
		logrus.Fields{
			"status":           response.Status,
			"message_type":     response.MessageType,
			"license_metadata": response.LicenseMetadata,
			"supported_tracks": response.SupportedTracks,
			"model":            response.Model,
			"security_level":   response.SecurityLevel,
			"session_state":    response.SessionState,
			"platform":         response.Platform,
			"client_info":      response.ClientInfo,
		})
	if response.Status == "OK" {
		logger.Info("License Request Success")
		return response, nil
	}
	logger.Error("License Request Failure")
	return nil, fmt.Errorf(response.Status)
}

func (wp *Proxy) ParseLicense(body []byte) (*LicenseResponse, error) {
	req, err := wp.parseLicense(body)
	if err != nil {
		return nil, err
	}
	return wp.sendReqeust(req)
}

func (wp *Proxy) parseLicense(body []byte) ([]byte, error) {
	message, err := json.Marshal(map[string]interface{}{
		"payload":    base64.StdEncoding.EncodeToString(body),
		"parse_only": true,
	})
	if err != nil {
		return nil, err
	}
	return wp.packingRequest(message)
}

func (wp *Proxy) buildCertificateRequest(body []byte) ([]byte, error) {
	message, err := json.Marshal(map[string]string{
		"payload": base64.StdEncoding.EncodeToString(body),
	})
	if err != nil {
		return nil, err
	}
	return wp.packingRequest(message)
}

func (wp *Proxy) buildLicenseRequest(body []byte, psshData *PsshData) ([]byte, error) {
	message, err := wp.LicenseAuthority.BuildLicenseMessage(body, psshData)
	if err != nil {
		return nil, err
	}
	messageJsonB, err := json.Marshal(message)
	if err != nil {
		return nil, err
	}
	return wp.packingRequest(messageJsonB)
}

func (wp *Proxy) sendReqeust(reqMessage []byte) (*LicenseResponse, error) {
	// Call Widevine License Server
	req, err := http.NewRequest("POST", wp.LicenseAuthority.GetLicenseServerURL(), bytes.NewBuffer(reqMessage))
	req.Header.Add("Content-Type", "application/json")
	response, err := wp.httpCaller.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	// Extract License
	b, _ := ioutil.ReadAll(response.Body)
	var lr LicenseResponse
	if err := json.Unmarshal(b, &lr); err != nil {
		wp.Logger.Error("Get License JSON Decode Error")
		return nil, err
	}
	return &lr, nil
}

func (wp *Proxy) generateSignature(payload []byte) ([]byte, error) {
	h := sha1.New()
	h.Write(payload)
	ciphertext, err := AESCBCEncrypt(wp.LicenseAuthority.GetSigningKey(), wp.LicenseAuthority.GetSigningIV(), h.Sum(nil))
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}

func (wp *Proxy) packingRequest(message []byte) ([]byte, error) {
	sign, err := wp.generateSignature(message)
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]string{
		"request":   base64.StdEncoding.EncodeToString(message),
		"signature": base64.StdEncoding.EncodeToString(sign),
		"signer":    wp.LicenseAuthority.GetProvider(),
	})
}

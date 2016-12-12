package ssh_ca_client

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/cloudtools/ssh-cert-authority/util"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type CertRequest struct {
	environment string
	reason      string
	validAfter  uint64
	validBefore uint64
	principals  []string
	publicKey   ssh.PublicKey
	keyID       string
	config      ssh_ca_util.RequesterConfig
}

func MakeCertRequest() CertRequest {
	var request CertRequest
	return request
}

type SigningRequest struct {
	signedCert ssh.Certificate
	requestID  string
	config     ssh_ca_util.SignerConfig
}

func MakeSigningRequest(cert ssh.Certificate, requestID string, config ssh_ca_util.SignerConfig) SigningRequest {
	var request SigningRequest
	request.signedCert = cert
	request.requestID = requestID
	request.config = config
	return request
}

func (req *SigningRequest) BuildWebRequest() url.Values {
	signedRequest := req.signedCert.Marshal()
	requestParameters := make(url.Values)
	requestParameters["cert"] = make([]string, 1)
	requestParameters["cert"][0] = base64.StdEncoding.EncodeToString(signedRequest)
	return requestParameters
}

func (req *SigningRequest) PostToWeb(requestParameters url.Values) error {
	resp, err := http.PostForm(req.config.SignerUrl+"cert/requests/"+req.requestID, requestParameters)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		respBuf, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %s: %s", resp.Status, string(respBuf))
	} else {
		return nil
	}
}

func (req *SigningRequest) DeleteToWeb(requestParameters url.Values) error {
	var client http.Client
	encodedParameters := requestParameters.Encode()
	request, err := http.NewRequest("DELETE", req.config.SignerUrl+"cert/requests/"+req.requestID+"?"+encodedParameters, nil)
	if err != nil {
		return err
	}
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(request)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		respBuf, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %s: %s", resp.Status, string(respBuf))
	} else {
		return nil
	}
}

func (req *CertRequest) SetConfig(config ssh_ca_util.RequesterConfig) error {
	if config.SignerUrl == "" {
		return fmt.Errorf("Signer URL is empty. This isn't going to work")
	}
	req.config = config
	return nil
}

func (req *CertRequest) SetEnvironment(environment string) error {
	if environment == "" {
		return fmt.Errorf("Environment must be set.")
	}
	if len(environment) > 50 {
		return fmt.Errorf("Environment is too long.")
	}
	req.environment = environment
	return nil
}

func (req *CertRequest) SetReason(reason string) error {
	if reason == "" {
		return fmt.Errorf("You must specify a reason.")
	}
	if len(reason) > 255 {
		return fmt.Errorf("Reason is too long.")
	}
	req.reason = reason
	return nil
}

func (req *CertRequest) SetValidAfter(validAfter time.Duration) error {
	timeNow := time.Now().Unix()
	req.validAfter = uint64(timeNow + int64(validAfter.Seconds()))
	return nil
}

func (req *CertRequest) SetValidBefore(validBefore time.Duration) error {
	timeNow := time.Now().Unix()
	req.validBefore = uint64(timeNow + int64(validBefore.Seconds()))
	return nil
}

func (req *CertRequest) SetPrincipalsFromString(principalsStr string) error {
	principals := strings.Split(strings.TrimSpace(principalsStr), ",")
	if principalsStr == "" {
		return fmt.Errorf("You didn't specify any principals. This cert is worthless.")
	}
	req.principals = principals
	return nil
}

func (req *CertRequest) SetPublicKey(pubKey ssh.PublicKey, keyID string) error {
	req.publicKey = pubKey
	req.keyID = keyID
	return nil
}

func (req *CertRequest) Validate() error {
	if req.validAfter >= req.validBefore {
		return fmt.Errorf("valid-after (%v) >= valid-before (%v). Which does not make sense.\n",
			time.Unix(int64(req.validAfter), 0), time.Unix(int64(req.validBefore), 0))
	}
	return nil
}

func (req *CertRequest) EncodeAsCertificate() (*ssh.Certificate, error) {
	err := req.Validate()
	if err != nil {
		return nil, err
	}

	newCert := ssh_ca_util.MakeCertificate()
	newCert.Key = req.publicKey
	newCert.Serial = 0
	newCert.CertType = ssh.UserCert
	newCert.KeyId = req.keyID
	newCert.ValidPrincipals = req.principals
	newCert.ValidAfter = req.validAfter
	newCert.ValidBefore = req.validBefore
	newCert.Extensions = make(map[string]string)
	newCert.Extensions["permit-agent-forwarding"] = ""
	newCert.Extensions["permit-port-forwarding"] = ""
	newCert.Extensions["permit-pty"] = ""
	newCert.Extensions["reason@cloudtools.github.io"] = req.reason
	newCert.Extensions["environment@cloudtools.github.io"] = req.environment
	return &newCert, nil
}

func (req *CertRequest) BuildWebRequest(signedCert []byte) url.Values {
	requestParameters := make(url.Values)
	requestParameters["cert"] = make([]string, 1)
	requestParameters["cert"][0] = base64.StdEncoding.EncodeToString(signedCert)

	return requestParameters
}

func (req *CertRequest) PostToWeb(requestParameters url.Values) (string, bool, error) {
	resp, err := http.PostForm(req.config.SignerUrl+"cert/requests", requestParameters)
	if err != nil {
		return "", false, err
	}
	respBuf, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return "", false, err
	}
	if resp.StatusCode == 201 || resp.StatusCode == 202 {
		signed := resp.StatusCode == 202
		return string(respBuf), signed, nil
	} else {
		return "", false, fmt.Errorf("Cert request rejected: %s", string(respBuf))
	}
}

type SlackWebhookInput struct {
	Text    string `json:"text"`
	Channel string `json:"channel"`
}

func PostToSlack(slackUrl, slackChannel, msg string) error {
	if slackUrl == "" || slackChannel == "" {
		return nil
	}
	var webhookInput SlackWebhookInput
	webhookInput.Text = msg
	if slackChannel != "" {
		webhookInput.Channel = slackChannel
	}
	output, err := json.Marshal(webhookInput)
	if err != nil {
		return err
	}
	requestParameters := make(url.Values)
	requestParameters["payload"] = make([]string, 1)
	requestParameters["payload"][0] = string(output)

	resp, err := http.PostForm(slackUrl, requestParameters)
	if err != nil {
		return err
	}
	respBuf, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return err
	}
	if resp.StatusCode == 200 {
		return nil
	} else {
		return fmt.Errorf("Slack post rejected: %s", string(respBuf))
	}
}

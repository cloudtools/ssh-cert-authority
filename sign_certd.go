package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/cloudtools/ssh-cert-authority/client"
	"github.com/cloudtools/ssh-cert-authority/util"
	"github.com/cloudtools/ssh-cert-authority/version"
	"github.com/codegangsta/cli"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"reflect"
	"regexp"
	"strings"
	"time"
)

// Yanked from PROTOCOL.certkeys
var supportedCriticalOptions = []string{
	"force-command",
	"source-address",
}

func isSupportedOption(x string) bool {
	for optionIdx := range supportedCriticalOptions {
		if supportedCriticalOptions[optionIdx] == x {
			return true
		}
	}
	return false
}

func areCriticalOptionsValid(criticalOptions map[string]string) error {
	for optionName := range criticalOptions {
		if !isSupportedOption(optionName) {
			return fmt.Errorf("Invalid critical option name: '%s'", optionName)
		}
	}
	return nil
}

type certRequest struct {
	// This struct tracks state for certificate requests. Imagine this one day
	// being stored in a persistent data store.
	request      *ssh.Certificate
	submitTime   time.Time
	environment  string
	signatures   map[string]bool
	certSigned   bool
	certRejected bool
	reason       string
}

func compareCerts(one, two *ssh.Certificate) bool {
	/* Compare two SSH certificates in a special way.

	The specialness is in that we expect these certs to be more or less the
	same but they will have been signed by different people. The act of signing
	the cert changes the Key, SignatureKey, Signature and Nonce fields of the
	Certificate struct so we compare the cert except for those fields.
	*/
	if one.Serial != two.Serial {
		return false
	}
	if one.CertType != two.CertType {
		return false
	}
	if one.KeyId != two.KeyId {
		return false
	}
	if !reflect.DeepEqual(one.ValidPrincipals, two.ValidPrincipals) {
		return false
	}
	if one.ValidAfter != two.ValidAfter {
		return false
	}
	if one.ValidBefore != two.ValidBefore {
		return false
	}
	if !reflect.DeepEqual(one.CriticalOptions, two.CriticalOptions) {
		return false
	}
	if !reflect.DeepEqual(one.Extensions, two.Extensions) {
		return false
	}
	if !bytes.Equal(one.Reserved, two.Reserved) {
		return false
	}
	if !reflect.DeepEqual(one.Key, two.Key) {
		return false
	}
	return true
}

func newcertRequest() certRequest {
	var cr certRequest
	cr.submitTime = time.Now()
	cr.certSigned = false
	cr.signatures = make(map[string]bool)
	return cr
}

type certRequestHandler struct {
	Config       map[string]ssh_ca_util.SignerdConfig
	state        map[string]certRequest
	sshAgentConn io.ReadWriter
}

type signingRequest struct {
	config      *ssh_ca_util.SignerdConfig
	environment string
	cert        *ssh.Certificate
}

func (h *certRequestHandler) setupPrivateKeys(config map[string]ssh_ca_util.SignerdConfig) error {
	for env, cfg := range config {
		if cfg.PrivateKeyFile != "" {
			keyContents, err := ioutil.ReadFile(cfg.PrivateKeyFile)
			if err != nil {
				return fmt.Errorf("Failed reading private key file %s: %v", cfg.PrivateKeyFile, err)
			}
			if strings.HasSuffix(cfg.PrivateKeyFile, ".kms") {
				var region string
				if cfg.KmsRegion != "" {
					region = cfg.KmsRegion
				} else {
					region, err = ec2metadata.New(session.New(), aws.NewConfig()).Region()
					if err != nil {
						return fmt.Errorf("Unable to determine our region: %s", err)
					}
				}
				svc := kms.New(session.New(), aws.NewConfig().WithRegion(region))
				params := &kms.DecryptInput{
					CiphertextBlob: keyContents,
				}
				resp, err := svc.Decrypt(params)
				if err != nil {
					// We try only one time to speak with KMS. If this pukes, and it
					// will occasionally because "the cloud", the caller is responsible
					// for trying again, possibly after a crash/restart.
					return fmt.Errorf("Unable to decrypt CA key: %v\n", err)
				}
				keyContents = resp.Plaintext
			}
			key, err := ssh.ParseRawPrivateKey(keyContents)
			if err != nil {
				return fmt.Errorf("Failed parsing private key %s: %v", cfg.PrivateKeyFile, err)
			}
			keyToAdd := agent.AddedKey{
				PrivateKey:   key,
				Comment:      fmt.Sprintf("ssh-cert-authority-%s-%s", env, cfg.PrivateKeyFile),
				LifetimeSecs: 0,
			}
			agentClient := agent.NewClient(h.sshAgentConn)
			err = agentClient.Add(keyToAdd)
			if err != nil {
				return fmt.Errorf("Unable to add private key %s: %v", cfg.PrivateKeyFile, err)
			}
			signer, err := ssh.NewSignerFromKey(key)
			if err != nil {
				return fmt.Errorf("Unable to create signer from pk %s: %v", cfg.PrivateKeyFile, err)
			}
			keyFp := ssh_ca_util.MakeFingerprint(signer.PublicKey().Marshal())
			log.Printf("Added private key for env %s: %s", env, keyFp)
			cfg = config[env]
			cfg.SigningKeyFingerprint = keyFp
			config[env] = cfg
		}
	}
	return nil
}

func (h *certRequestHandler) createSigningRequest(rw http.ResponseWriter, req *http.Request) {
	err := req.ParseForm()
	if err != nil {
		http.Error(rw, fmt.Sprintf("%v", err), http.StatusBadRequest)
		return
	}

	cert, err := h.extractCertFromRequest(req)
	if err != nil {
		http.Error(rw, fmt.Sprintf("%v", err), http.StatusBadRequest)
		return
	}

	environment, ok := cert.Extensions["environment@cloudtools.github.io"]
	if !ok || environment == "" {
		http.Error(rw, "You forgot to send in the environment", http.StatusBadRequest)
		return
	}

	reason, ok := cert.Extensions["reason@cloudtools.github.io"]
	if !ok || reason == "" {
		http.Error(rw, "You forgot to send in a reason", http.StatusBadRequest)
		return
	}

	config, ok := h.Config[environment]
	if !ok {
		http.Error(rw, "Unknown environment.", http.StatusBadRequest)
		return
	}

	err = h.validateCert(cert, config.AuthorizedUsers)
	if err != nil {
		log.Printf("Invalid certificate signing request received from %s, ignoring", req.RemoteAddr)
		http.Error(rw, fmt.Sprintf("%v", err), http.StatusBadRequest)
		return
	}

	// Ideally we put the critical options into the cert and let validateCert
	// do the validation. However, this also checks the signature on the cert
	// which would fail if we modified it prior to validation. So we validate
	// by hand.
	if len(config.CriticalOptions) > 0 {
		for optionName, optionVal := range config.CriticalOptions {
			cert.CriticalOptions[optionName] = optionVal
		}
	}

	requestID := make([]byte, 8)
	rand.Reader.Read(requestID)
	requestIDStr := base32.StdEncoding.EncodeToString(requestID)
	requestIDStr = strings.Replace(requestIDStr, "=", "", 10)
	// the serial number is the same as the request id, just encoded differently.
	var nextSerial uint64
	nextSerial = 0
	for _, byteVal := range requestID {
		nextSerial <<= 8
		nextSerial |= uint64(byteVal)
	}

	requesterFp := ssh_ca_util.MakeFingerprint(cert.SignatureKey.Marshal())

	signed, err := h.saveSigningRequest(config, environment, reason, requestIDStr, nextSerial, cert)
	if err != nil {
		http.Error(rw, fmt.Sprintf("Request not made: %v", err), http.StatusBadRequest)
		return
	}

	// Serial and id are the same value, just encoded differently. Logging them
	// both because they didn't use to be the same value and folks may be
	// parsing these log messages and I don't want to break the format.
	log.Printf("Cert request serial %d id %s env %s from %s (%s) @ %s principals %v valid from %d to %d for '%s'\n",
		cert.Serial, requestIDStr, environment, requesterFp, config.AuthorizedUsers[requesterFp],
		req.RemoteAddr, cert.ValidPrincipals, cert.ValidAfter, cert.ValidBefore, reason)

	if config.SlackUrl != "" {
		slackMsg := fmt.Sprintf("SSH cert request from %s with id %s for %s", config.AuthorizedUsers[requesterFp], requestIDStr, reason)
		err = ssh_ca_client.PostToSlack(config.SlackUrl, config.SlackChannel, slackMsg)
		if err != nil {
			log.Printf("Unable to post to slack: %v", err)
		}
	}

	var returnStatus int
	if signed {
		slackMsg := fmt.Sprintf("SSH cert request %s auto signed.", requestIDStr)
		err := ssh_ca_client.PostToSlack(config.SlackUrl, config.SlackChannel, slackMsg)
		if err != nil {
			log.Printf("Unable to post to slack for %s: %v", requestIDStr, err)
		}
		returnStatus = http.StatusAccepted
	} else {
		returnStatus = http.StatusCreated
	}
	rw.WriteHeader(returnStatus)
	rw.Write([]byte(requestIDStr))

	return
}

func (h *certRequestHandler) saveSigningRequest(config ssh_ca_util.SignerdConfig, environment, reason, requestIDStr string, requestSerial uint64, cert *ssh.Certificate) (bool, error) {
	requesterFp := ssh_ca_util.MakeFingerprint(cert.SignatureKey.Marshal())

	maxValidBefore := uint64(time.Now().Add(time.Duration(config.MaxCertLifetime) * time.Second).Unix())

	if config.MaxCertLifetime != 0 && cert.ValidBefore > maxValidBefore {
		return false, fmt.Errorf("Certificate is valid longer than maximum permitted by configuration %d > %d",
			cert.ValidBefore, maxValidBefore)
	}

	// We override keyid here so that its a server controlled value. Instead of
	// letting a requester attempt to spoof it.
	var ok bool
	cert.KeyId, ok = config.AuthorizedUsers[requesterFp]
	if !ok {
		return false, fmt.Errorf("Requester fingerprint (%s) not found in config", requesterFp)
	}

	if requestSerial == 0 {
		return false, fmt.Errorf("Serial number not set.")
	}
	cert.Serial = requestSerial

	certRequest := newcertRequest()
	certRequest.request = cert
	if environment == "" {
		return false, fmt.Errorf("Environment is a required field")
	}
	certRequest.environment = environment

	if reason == "" {
		return false, fmt.Errorf("Reason is a required field")
	}
	certRequest.reason = reason

	if len(requestIDStr) < 12 {
		return false, fmt.Errorf("Request id is too short to be useful.")
	}
	_, ok = h.state[requestIDStr]
	if ok {
		return false, fmt.Errorf("Request id '%s' already in use.", requestIDStr)
	}
	h.state[requestIDStr] = certRequest

	// This is the special case of supporting auto-signing.
	if config.NumberSignersRequired < 0 {
		signed, err := h.maybeSignWithCa(requestIDStr, config.NumberSignersRequired, config.SigningKeyFingerprint)
		if signed && err == nil {
			return true, nil
		}
	}

	return false, nil
}

func (h *certRequestHandler) extractCertFromRequest(req *http.Request) (*ssh.Certificate, error) {

	if req.Form["cert"] == nil || len(req.Form["cert"]) == 0 {
		err := errors.New("Please specify exactly one cert request")
		return nil, err
	}

	rawCertRequest, err := base64.StdEncoding.DecodeString(req.Form["cert"][0])
	if err != nil {
		err := errors.New("Unable to base64 decode cert request")
		return nil, err
	}
	pubKey, err := ssh.ParsePublicKey(rawCertRequest)
	if err != nil {
		err := errors.New("Unable to parse cert request")
		return nil, err
	}

	return pubKey.(*ssh.Certificate), nil
}

func (h *certRequestHandler) validateCert(cert *ssh.Certificate, authorizedSigners map[string]string) error {
	var certChecker ssh.CertChecker
	certChecker.IsUserAuthority = func(auth ssh.PublicKey) bool {
		fingerprint := ssh_ca_util.MakeFingerprint(auth.Marshal())
		_, ok := authorizedSigners[fingerprint]
		return ok
	}
	certChecker.SupportedCriticalOptions = supportedCriticalOptions

	err := certChecker.CheckCert(cert.ValidPrincipals[0], cert)
	if err != nil {
		err := fmt.Errorf("Cert not valid: %v", err)
		return err
	}
	return nil
}

type listResponseElement struct {
	Signed             bool
	Rejected           bool
	CertBlob           string
	NumSignatures      int
	SignaturesRequired int
	Serial             uint64
	Environment        string
	Reason             string
	Cert               *ssh.Certificate
}
type certRequestResponse map[string]listResponseElement

func newResponseElement(cert *ssh.Certificate, certBlob string, signed bool, rejected bool, numSignatures, signaturesRequired int, serial uint64, reason string, environment string) listResponseElement {
	var element listResponseElement
	element.Cert = cert
	element.CertBlob = certBlob
	element.Signed = signed
	element.Rejected = rejected
	element.NumSignatures = numSignatures
	element.SignaturesRequired = signaturesRequired
	element.Serial = serial
	element.Reason = reason
	element.Environment = environment
	return element
}

func (h *certRequestHandler) listEnvironments(rw http.ResponseWriter, req *http.Request) {
	var environments []string
	for k := range h.Config {
		environments = append(environments, k)
	}
	result, err := json.Marshal(environments)
	if err != nil {
		http.Error(rw, fmt.Sprintf("Unable to marshal environment names: %v", err), http.StatusInternalServerError)
		return
	}
	log.Printf("List environments received from '%s'\n", req.RemoteAddr)
	rw.Header().Set("Content-Type", "application/json; charset=utf-8")
	rw.Write(result)
}

func (h *certRequestHandler) listPendingRequests(rw http.ResponseWriter, req *http.Request) {
	var certRequestID string

	err := req.ParseForm()
	if err != nil {
		http.Error(rw, fmt.Sprintf("%v", err), http.StatusBadRequest)
		return
	}

	certRequestIDs, ok := req.Form["certRequestId"]
	if ok {
		certRequestID = certRequestIDs[0]
	}

	matched, _ := regexp.MatchString("^[A-Z2-7=]{10,16}$", certRequestID)
	if certRequestID != "" && !matched {
		http.Error(rw, "Invalid certRequestId", http.StatusBadRequest)
		return
	}
	log.Printf("List pending requests received from %s for request id '%s'\n",
		req.RemoteAddr, certRequestID)

	foundSomething := false
	results := make(certRequestResponse)
	for k, v := range h.state {
		encodedCert := base64.StdEncoding.EncodeToString(v.request.Marshal())
		element := newResponseElement(v.request, encodedCert, v.certSigned, v.certRejected, len(v.signatures), h.Config[v.environment].NumberSignersRequired, v.request.Serial, v.reason, v.environment)
		// Two ways to use this URL. If caller specified a certRequestId
		// then we return only that one. Otherwise everything.
		if certRequestID == "" {
			results[k] = element
			foundSomething = true
		} else {
			if certRequestID == k {
				results[k] = element
				foundSomething = true
				break
			}
		}
	}
	if foundSomething {
		output, err := json.Marshal(results)
		if err != nil {
			http.Error(rw, fmt.Sprintf("Trouble marshaling json response %v", err), http.StatusInternalServerError)
			return
		}
		rw.Header().Set("Content-Type", "application/json; charset=utf-8")
		rw.Write(output)
	} else {
		http.Error(rw, fmt.Sprintf("No certs found."), http.StatusNotFound)
		return
	}
}

func (h *certRequestHandler) getRequestStatus(rw http.ResponseWriter, req *http.Request) {
	uriVars := mux.Vars(req)
	requestID := uriVars["requestID"]

	type Response struct {
		certSigned   bool
		certRejected bool
		cert         string
	}
	if h.state[requestID].certSigned {
		rw.Write([]byte(h.state[requestID].request.Type()))
		rw.Write([]byte(" "))
		rw.Write([]byte(base64.StdEncoding.EncodeToString(h.state[requestID].request.Marshal())))
		rw.Write([]byte("\n"))
	} else if h.state[requestID].certRejected {
		http.Error(rw, "Cert request was rejected.", http.StatusPreconditionFailed)
	} else {
		http.Error(rw, "Cert not signed yet.", http.StatusPreconditionFailed)
	}
}

func (h *certRequestHandler) signOrRejectRequest(rw http.ResponseWriter, req *http.Request) {
	requestID := mux.Vars(req)["requestID"]
	originalRequest, ok := h.state[requestID]
	if !ok {
		http.Error(rw, "Unknown request id", http.StatusNotFound)
		return
	}
	if originalRequest.certSigned {
		http.Error(rw, "Request already signed.", http.StatusConflict)
		return
	}
	if originalRequest.certRejected {
		http.Error(rw, "Request already rejected.", http.StatusConflict)
		return
	}

	err := req.ParseForm()
	if err != nil {
		http.Error(rw, fmt.Sprintf("%v", err), http.StatusBadRequest)
		return
	}

	envConfig, ok := h.Config[originalRequest.environment]
	if !ok {
		http.Error(rw, "Original request found to have an invalid env. Weird.", http.StatusBadRequest)
		return
	}

	signedCert, err := h.extractCertFromRequest(req)
	if err != nil {
		log.Printf("Unable to extract certificate signing request from %s, ignoring", req.RemoteAddr)
		http.Error(rw, fmt.Sprintf("%v", err), http.StatusBadRequest)
		return
	}
	err = h.validateCert(signedCert, envConfig.AuthorizedSigners)
	if err != nil {
		log.Printf("Invalid certificate signing request received from %s, ignoring", req.RemoteAddr)
		http.Error(rw, fmt.Sprintf("%v", err), http.StatusBadRequest)
		return
	}

	signerFp := ssh_ca_util.MakeFingerprint(signedCert.SignatureKey.Marshal())

	// Verifying that the cert being posted to us here matches the one in the
	// request. That is, that an attacker isn't using an old signature to sign a
	// new/different request id
	requestedCert := h.state[requestID].request
	if !compareCerts(requestedCert, signedCert) {
		log.Printf("Signature was valid, but cert didn't match from %s.", req.RemoteAddr)
		log.Printf("Orig req: %#v\n", requestedCert)
		log.Printf("Sign req: %#v\n", signedCert)
		http.Error(rw, "Signature was valid, but cert didn't match.", http.StatusBadRequest)
		return
	}
	log.Printf("Signature for serial %d id %s received from %s (%s) @ %s and determined valid\n",
		signedCert.Serial, requestID, signerFp, envConfig.AuthorizedSigners[signerFp], req.RemoteAddr)
	if req.Method == "POST" {
		err = h.addConfirmation(requestID, signerFp, envConfig)
	} else {
		err = h.rejectRequest(requestID, signerFp, envConfig)
	}
	if err != nil {
		http.Error(rw, fmt.Sprintf("%v", err), http.StatusNotFound)
	}
}

func (h *certRequestHandler) rejectRequest(requestID string, signerFp string, envConfig ssh_ca_util.SignerdConfig) error {
	log.Printf("Reject received for id %s", requestID)
	stateInfo := h.state[requestID]
	stateInfo.certRejected = true
	// this is weird. see: https://code.google.com/p/go/issues/detail?id=3117
	h.state[requestID] = stateInfo
	return nil
}

func (h *certRequestHandler) addConfirmation(requestID string, signerFp string, envConfig ssh_ca_util.SignerdConfig) error {
	if h.state[requestID].certRejected {
		return fmt.Errorf("Attempt to sign a rejected cert.")
	}
	h.state[requestID].signatures[signerFp] = true

	if envConfig.SlackUrl != "" {
		slackMsg := fmt.Sprintf("SSH cert %s signed by %s making %d/%d signatures.",
			requestID, envConfig.AuthorizedSigners[signerFp],
			len(h.state[requestID].signatures), envConfig.NumberSignersRequired)
		err := ssh_ca_client.PostToSlack(envConfig.SlackUrl, envConfig.SlackChannel, slackMsg)
		if err != nil {
			log.Printf("Unable to post to slack for %s: %v", requestID, err)
		}
	}
	signed, err := h.maybeSignWithCa(requestID, envConfig.NumberSignersRequired, envConfig.SigningKeyFingerprint)
	if signed && err == nil {
		slackMsg := fmt.Sprintf("SSH cert request %s fully signed.", requestID)
		err := ssh_ca_client.PostToSlack(envConfig.SlackUrl, envConfig.SlackChannel, slackMsg)
		if err != nil {
			log.Printf("Unable to post to slack for %s: %v", requestID, err)
		}
	}
	return err
}

func (h *certRequestHandler) maybeSignWithCa(requestID string, numSignersRequired int, signingKeyFingerprint string) (bool, error) {
	if len(h.state[requestID].signatures) >= numSignersRequired {
		if h.sshAgentConn == nil {
			// This is used for testing. We're effectively disabling working
			// with the ssh agent to avoid needing to mock it.
			log.Print("ssh agent uninitialized, will not attempt signing. This is normal in unittests")
			return true, nil
		}
		log.Printf("Received %d signatures for %s, signing now.\n", len(h.state[requestID].signatures), requestID)
		signer, err := ssh_ca_util.GetSignerForFingerprint(signingKeyFingerprint, h.sshAgentConn)
		if err != nil {
			log.Printf("Couldn't find signing key for request %s, unable to sign request\n", requestID)
			return false, fmt.Errorf("Couldn't find signing key, unable to sign. Sorry.")
		}
		stateInfo := h.state[requestID]
		for extensionName := range stateInfo.request.Extensions {
			// sshd up to version 6.8 has a bug where optional extensions are
			// treated as critical. If a cert contains any non-standard
			// extensions, like ours, the server rejects the cert because it
			// doesn't understand the extension. To cope with this we simply
			// strip our non-standard extensions before doing the final
			// signature. https://bugzilla.mindrot.org/show_bug.cgi?id=2387
			if strings.Contains(extensionName, "@") {
				delete(stateInfo.request.Extensions, extensionName)
			}
		}
		stateInfo.request.SignCert(rand.Reader, signer)
		stateInfo.certSigned = true
		// this is weird. see: https://code.google.com/p/go/issues/detail?id=3117
		h.state[requestID] = stateInfo
		return true, nil
	}
	return false, nil
}

func signdFlags() []cli.Flag {
	home := os.Getenv("HOME")
	if home == "" {
		home = "/"
	}
	configPath := home + "/.ssh_ca/sign_certd_config.json"

	return []cli.Flag{
		cli.StringFlag{
			Name:  "config-file",
			Value: configPath,
			Usage: "Path to config.json",
		},
		cli.StringFlag{
			Name:  "listen-address",
			Value: "127.0.0.1:8080",
			Usage: "HTTP service address",
		},
		cli.BoolFlag{
			Name: "reverse-proxy",
			Usage: "Set when service is behind a reverse proxy, like nginx",
			EnvVar: "SSH_CERT_AUTHORITY_PROXY",
		},
	}
}

func signCertd(c *cli.Context) error {
	configPath := c.String("config-file")
	config := make(map[string]ssh_ca_util.SignerdConfig)
	err := ssh_ca_util.LoadConfig(configPath, &config)
	if err != nil {
		return cli.NewExitError(fmt.Sprintf("Load Config failed: %s", err), 1)
	}
	for envName, configObj := range config {
		err = areCriticalOptionsValid(configObj.CriticalOptions)
		if err != nil {
			return cli.NewExitError(fmt.Sprintf("Error validation config for env '%s': %s", envName, err), 1)
		}
	}
	err = runSignCertd(config, c.String("listen-address"), c.Bool("reverse-proxy"))
	return err
}

func makeCertRequestHandler(config map[string]ssh_ca_util.SignerdConfig) certRequestHandler {
	var requestHandler certRequestHandler
	requestHandler.Config = config
	requestHandler.state = make(map[string]certRequest)
	return requestHandler
}

func runSignCertd(config map[string]ssh_ca_util.SignerdConfig, addr string, is_proxied bool) error {
	log.Println("Server running version", version.BuildVersion)
	log.Println("Using SSH agent at", os.Getenv("SSH_AUTH_SOCK"))

	sshAgentConn, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
	if err != nil {
		return cli.NewExitError(fmt.Sprintf("Dial failed: %s", err), 1)
	}
	requestHandler := makeCertRequestHandler(config)
	requestHandler.sshAgentConn = sshAgentConn
	err = requestHandler.setupPrivateKeys(config)
	if err != nil {
		return cli.NewExitError(fmt.Sprintf("Failed CA key load: %v\n", err), 1)
	}

	log.Printf("Server started with config %#v\n", config)

	r := mux.NewRouter()
	requests := r.Path("/cert/requests").Subrouter()
	requests.Methods("POST").HandlerFunc(requestHandler.createSigningRequest)
	requests.Methods("GET").HandlerFunc(requestHandler.listPendingRequests)
	request := r.Path("/cert/requests/{requestID}").Subrouter()
	request.Methods("GET").HandlerFunc(requestHandler.getRequestStatus)
	request.Methods("POST", "DELETE").HandlerFunc(requestHandler.signOrRejectRequest)
	environments := r.Path("/config/environments").Subrouter()
	environments.Methods("GET").HandlerFunc(requestHandler.listEnvironments)

	if is_proxied {
		http.ListenAndServe(addr, handlers.ProxyHeaders(r))
	} else {
		http.ListenAndServe(addr, r)
	}
	return nil
}

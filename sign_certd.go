package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/cloudtools/ssh-cert-authority/client"
	"github.com/cloudtools/ssh-cert-authority/util"
	"github.com/codegangsta/cli"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/ssh"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"reflect"
	"regexp"
	"strings"
	"time"
)

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
	NextSerial   chan uint64
}

type signingRequest struct {
	config      *ssh_ca_util.SignerdConfig
	environment string
	cert        *ssh.Certificate
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

	requestID := make([]byte, 10)
	rand.Reader.Read(requestID)
	requestIDStr := base32.StdEncoding.EncodeToString(requestID)
	nextSerial := <-h.NextSerial

	err = h.saveSigningRequest(config, environment, reason, requestIDStr, nextSerial, cert)
	if err != nil {
		http.Error(rw, fmt.Sprintf("Request not made: %v", err), http.StatusBadRequest)
		return
	}

	requesterFp := ssh_ca_util.MakeFingerprint(cert.SignatureKey.Marshal())
	log.Printf("Cert request serial %d id %s env %s from %s (%s) @ %s principals %v valid from %d to %d for '%s'\n",
		cert.Serial, requestIDStr, environment, requesterFp, config.AuthorizedUsers[requesterFp],
		req.RemoteAddr, cert.ValidPrincipals, cert.ValidAfter, cert.ValidBefore, reason)
	rw.WriteHeader(http.StatusCreated)
	rw.Write([]byte(requestIDStr))

	if config.SlackUrl != "" {
		slackMsg := fmt.Sprintf("SSH cert request from %s with id %s for %s", config.AuthorizedUsers[requesterFp], requestIDStr, reason)
		err = ssh_ca_client.PostToSlack(config.SlackUrl, config.SlackChannel, slackMsg)
		if err != nil {
			log.Printf("Unable to post to slack: %v", err)
		}
	}

	return
}

func (h *certRequestHandler) saveSigningRequest(config ssh_ca_util.SignerdConfig, environment, reason, requestIDStr string, requestSerial uint64, cert *ssh.Certificate) error {
	requesterFp := ssh_ca_util.MakeFingerprint(cert.SignatureKey.Marshal())

	maxValidBefore := uint64(time.Now().Add(time.Duration(config.MaxCertLifetime) * time.Second).Unix())

	if config.MaxCertLifetime != 0 && cert.ValidBefore > maxValidBefore {
		return fmt.Errorf("Certificate is valid longer than maximum permitted by configuration %d > %d",
			cert.ValidBefore, maxValidBefore)
	}

	// We override keyid here so that its a server controlled value. Instead of
	// letting a requester attempt to spoof it.
	var ok bool
	cert.KeyId, ok = config.AuthorizedUsers[requesterFp]
	if !ok {
		return fmt.Errorf("Requester fingerprint (%s) not found in config", requesterFp)
	}

	if requestSerial == 0 {
		return fmt.Errorf("Serial number not set.")
	}
	cert.Serial = requestSerial

	certRequest := newcertRequest()
	certRequest.request = cert
	if environment == "" {
		return fmt.Errorf("Environment is a required field")
	}
	certRequest.environment = environment

	if reason == "" {
		return fmt.Errorf("Reason is a required field")
	}
	certRequest.reason = reason

	if len(requestIDStr) < 12 {
		return fmt.Errorf("Request id is too short to be useful.")
	}
	_, ok = h.state[requestIDStr]
	if ok {
		return fmt.Errorf("Request id '%s' already in use.", requestIDStr)
	}
	h.state[requestIDStr] = certRequest

	return nil
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
	certChecker.IsAuthority = func(auth ssh.PublicKey) bool {
		fingerprint := ssh_ca_util.MakeFingerprint(auth.Marshal())
		_, ok := authorizedSigners[fingerprint]
		return ok
	}
	err := certChecker.CheckCert(cert.ValidPrincipals[0], cert)
	if err != nil {
		err := fmt.Errorf("Cert not valid: %v", err)
		return err
	}
	return nil
}

type listResponseElement struct {
	Signed   bool
	CertBlob string
}
type certRequestResponse map[string]listResponseElement

func newResponseElement(certBlob string, signed bool) listResponseElement {
	var element listResponseElement
	element.CertBlob = certBlob
	element.Signed = signed
	return element
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

	matched, _ := regexp.MatchString("^[A-Z2-7=]{16}$", certRequestID)
	if certRequestID != "" && !matched {
		http.Error(rw, "Invalid certRequestId", http.StatusBadRequest)
		return
	}
	log.Printf("List pending requests received from %s for request id '%s'\n",
		req.RemoteAddr, certRequestID)

	foundSomething := false
	results := make(map[string]listResponseElement)
	for k, v := range h.state {
		encodedCert := base64.StdEncoding.EncodeToString(v.request.Marshal())
		element := newResponseElement(encodedCert, v.certSigned)
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
		err = h.addConfirmation(requestID, signerFp, envConfig, true)
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

func (h *certRequestHandler) addConfirmation(requestID string, signerFp string, envConfig ssh_ca_util.SignerdConfig, actuallySign bool) error {
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
	signed, err := h.maybeSignWithCa(requestID, envConfig.NumberSignersRequired, envConfig.SigningKeyFingerprint, actuallySign)
	if signed && err == nil {
		slackMsg := fmt.Sprintf("SSH cert request %s fully signed.", requestID)
		err := ssh_ca_client.PostToSlack(envConfig.SlackUrl, envConfig.SlackChannel, slackMsg)
		if err != nil {
			log.Printf("Unable to post to slack for %s: %v", requestID, err)
		}
	}
	return err
}

func (h *certRequestHandler) maybeSignWithCa(requestID string, numSignersRequired int, signingKeyFingerprint string, actuallySign bool) (bool, error) {
	if len(h.state[requestID].signatures) >= numSignersRequired {
		if !actuallySign {
			// This is used for testing. We're effectively disabling working
			// with the ssh agent to avoid needing to mock it.
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
	}
}

func signCertd(c *cli.Context) {
	configPath := c.String("config-file")
	config := make(map[string]ssh_ca_util.SignerdConfig)
	err := ssh_ca_util.LoadConfig(configPath, &config)
	if err != nil {
		log.Println("Load Config failed:", err)
		os.Exit(1)
	}
	runSignCertd(config)
}

func makeCertRequestHandler(config map[string]ssh_ca_util.SignerdConfig) certRequestHandler {
	var requestHandler certRequestHandler
	requestHandler.Config = config
	requestHandler.state = make(map[string]certRequest)
	requestHandler.NextSerial = make(chan uint64)
	go func() {
		var serial uint64
		for serial = 1; ; serial++ {
			requestHandler.NextSerial <- serial
		}
	}()
	return requestHandler
}

func runSignCertd(config map[string]ssh_ca_util.SignerdConfig) {
	log.Println("Server running version", ssh_ca_util.BuildVersion)
	log.Println("Server started with config", config)
	log.Println("Using SSH agent at", os.Getenv("SSH_AUTH_SOCK"))

	sshAgentConn, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
	if err != nil {
		log.Println("Dial failed:", err)
		os.Exit(1)
	}
	requestHandler := makeCertRequestHandler(config)
	requestHandler.sshAgentConn = sshAgentConn

	r := mux.NewRouter()
	requests := r.Path("/cert/requests").Subrouter()
	requests.Methods("POST").HandlerFunc(requestHandler.createSigningRequest)
	requests.Methods("GET").HandlerFunc(requestHandler.listPendingRequests)
	request := r.Path("/cert/requests/{requestID}").Subrouter()
	request.Methods("GET").HandlerFunc(requestHandler.getRequestStatus)
	request.Methods("POST", "DELETE").HandlerFunc(requestHandler.signOrRejectRequest)
	http.ListenAndServe(":8080", r)
}

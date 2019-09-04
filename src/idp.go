package main

// to convert .12 files to .cer + .key file combination
// $ openssl pkcs12 -in client-id.p12 -clcerts -nokeys -out client-id.cer
// $ openssl pkcs12 -in client-id.p12 -clcerts -nodes -nocerts | openssl rsa > client-id.key

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"log"
	"math/big"
	"strconv"
	"strings"
	"time"

	//    "crypto/x509"
	"io/ioutil"
	//    "io"
	"bytes"
	//	"strconv"
	"errors"
	"net/http"
)

type Client_Validation_Ticket struct {
	cache       *Identity_Profile
	added       time.Time
	serial_no   big.Int
	device_name string
	device_type string
}

var validation_tickets = make(map[string]Client_Validation_Ticket)

func extract_client_certificate(req *http.Request) (*x509.Certificate, string) {
	var client_cert *x509.Certificate

	// if the certificate is sent in the request
	if len(req.TLS.PeerCertificates) > 0 {
		client_cert = req.TLS.PeerCertificates[0]

		// verify expiry
		if time.Now().Before(client_cert.NotBefore) || time.Now().After(client_cert.NotAfter) {
			return nil, "Your SSL Client Certificate expired on " + client_cert.NotAfter.Format("2006-01-02 15:04:05")
		}

	} else {
		return nil, "No Client Certificate was sent to the server, please verify whether your browser has the proper SSL CLient Ceritficate."
	}

	return client_cert, ""
}

// Populate the IDP headers with the certificate related information
func populate_request_headers(from *Client_Validation_Ticket, req *http.Request) {
	req.Header.Set("X-Client-Serial", from.serial_no.String())
	req.Header.Set("X-Client-Device", from.device_name)
	req.Header.Set("X-Client-Type", from.device_type)
	req.Header.Set("X-Client-Roles", strings.Join(from.cache.ServiceRoles, ","))
	// req.Header.Set("X-Client-Local-User", ....)
}

func validate_client_certificate(res http.ResponseWriter, req *http.Request) (*Client_Validation_Ticket, bool) {
	// extract the certificate
	client_cert, error_reason := extract_client_certificate(req)

	var cached_validation Client_Validation_Ticket

	// if no elementary errors have been found
	if error_reason == "" {

		cached_validation = validation_tickets[client_cert.SerialNumber.String()]

		// if we have a cache that is not older than 5 minutes, we skip
		if cached_validation.cache == nil || time.Now().Sub(cached_validation.added).Seconds() > 60 {
			log.Printf("refreshing IDP: %f\n", time.Now().Sub(cached_validation.added).Seconds())
			ans := identity_inquiry(client_cert.SerialNumber.String())
			// "476701752658536845")

			if ans.SimpleResponse.Outcome != "" {
				// in case of errors we receive simple response from the server

				if ans.SimpleResponse.Outcome == "PB 0003 Identity Plus anonymous certificate needs validation" {
					// if the certificate is clean but requires validation we redirect
					// we first create a certificate discovery intent
					log.Printf("redirecting: %s\n", "https://"+req.Host+req.URL.RequestURI())
					ans = create_intent("discover", "https://"+req.Host+req.URL.RequestURI())

					if ans.IntentReference.Outcome != "" {
						// intent created and we received a reference
						res.Header().Add("Location", "https://signon.identity.plus/"+ans.IntentReference.Value)
						res.WriteHeader(http.StatusFound)
						res.Write([]byte(""))

						// we write the response, so no going forward to the proxy
						return nil, false
					}
				}

				error_reason = ans.SimpleResponse.Outcome

			} else if ans.IdentityProfile.Outcome != "" {

				// in case we receive a profile
				// for this, the certificate needs to be valid, not timed out or reported
				if ans.IdentityProfile.Outcome[0:2] == "OK" {

					// the user has a role in the server
					// let's cache this result for a few minutes
					// if a cache exists, we will overwrite it
					cached_validation = Client_Validation_Ticket{
						cache:       &ans.IdentityProfile,
						added:       time.Now(),
						serial_no:   *client_cert.SerialNumber,
						device_name: client_cert.Subject.CommonName,
						device_type: client_cert.Subject.OrganizationalUnit[0],
					}

					validation_tickets[client_cert.SerialNumber.String()] = cached_validation

					// log the
					log.Printf("    Serial Number: %s\n", cached_validation.serial_no.String())
					log.Printf("    Device Name: %s\n", cached_validation.device_name)
					log.Printf("    Device Type: %s\n", client_cert.Subject.OrganizationalUnit)
					log.Printf("    Roles: %s\n", cached_validation.cache.ServiceRoles)

				} else {
					error_reason = ans.SimpleResponse.Outcome
				}

			} else {
				error_reason = ans.SimpleResponse.Outcome
			}
		}

	}

	// we will look a the roles now, and if there are no roles defined
	// the client clearly has no business here
	if error_reason == "" && len(cached_validation.cache.ServiceRoles) == 0 {
		error_reason = "Your certificate is valid, but you have no roles on this server"
	}

	if error_reason != "" {
		log.Printf("sending forbidden: %s\n", error_reason)
		res.WriteHeader(http.StatusForbidden)
		res.Write([]byte(strings.Replace(load_balancer.response_403, "${reason}", "<li>"+error_reason+"</li>", -1)))

		// we write the response, so no going forward to the proxy
		return nil, false
	}

	// means it allows the user to continue execution through he proxy
	return &cached_validation, true
}

func service_identity_renewal(must_renew bool) IDP_Response {
	ans := do_put("{\"Service-Identity-Request\":{\"force-renewal\": " + strconv.FormatBool(must_renew) + "}}")
	return ans

}

func identity_inquiry(serial_no string) IDP_Response {

	ans := do_get("{\"Identity-Inquiry\":{\"serial-number\": \"" + serial_no + "\"}}")
	return ans

}

func create_intent(intent_type string, return_url string) IDP_Response {

	ans := do_put("{\"Intent\":{ \"type\": \"" + intent_type + "\", \"return-url\": \"" + return_url + "\", \"strict-massl\":true}}")
	return ans

}

//
// just a set of wrappers around the methods
//
func do_get(request_body string) IDP_Response {
	return do_call("GET", request_body)
}

func do_put(request_body string) IDP_Response {
	return do_call("PUT", request_body)
}

func do_post(request_body string) IDP_Response {
	return do_call("POST", request_body)
}

func do_delete(request_body string) IDP_Response {
	return do_call("DELETE", request_body)
}

//
// returns 2 values int this order: the http response status (int) and the body of the answer ([]byte)
// - if the http response code is anything but 200, the body should be expected to contain
//   some error description
// - an error of 600 as response code means the call could not be made due to whatever reason
// - 5xx errors mean the request was made, but generated a server error
//
func do_call(method string, request_body string) IDP_Response {

	client, err := client()

	if err != nil {
		oc := Simple_Response{Outcome: ("Unable to create http client: " + err.Error())}
		return IDP_Response{http_code: 600, SimpleResponse: oc}
	}

	// var body_reader io.Reader
	var jsonStr = []byte(request_body)
	client_request, err := http.NewRequest(method, "https://api.identity.plus/v1", bytes.NewBuffer(jsonStr))
	client_request.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(client_request)

	defer func() {
		// only close body if it exists to prevent nil reference
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
	}()

	if err != nil {
		oc := Simple_Response{Outcome: ("error during https call: " + err.Error())}
		return IDP_Response{http_code: 600, SimpleResponse: oc}
	}

	bodyBytes, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		oc := Simple_Response{Outcome: ("error decoding https answer: " + err.Error())}
		return IDP_Response{http_code: 600, SimpleResponse: oc}
	}

	log.Printf("idp response: %s\n", string(bodyBytes))

	var response IDP_Response

	json.Unmarshal(bodyBytes, &response)
	response.http_code = resp.StatusCode

	return response
}

//
// Lazily creates a http client and caches it so that next time it does not have to create it
// also, this leverages re-use of TCP/TLS connection such that we do not have to do tripple
// handshake at every call: 7ZR8XFK36HZEYHDVTTZU
//
var __client *http.Client

func client() (*http.Client, error) {

	// create the client if not yet created
	if __client == nil {

		if load_balancer.AgentKey == "" || load_balancer.AgentCertificate == "" {
			return nil, errors.New("client certificate or key not properly specified. They need to be in separate files as DER Encoded")
		}

		clientCert, err := tls.LoadX509KeyPair(load_balancer.AgentCertificate, load_balancer.AgentKey)

		if err != nil {
			return nil, errors.New("error loading key material: " + err.Error())
		}

		tlsConfig := tls.Config{
			Certificates: []tls.Certificate{clientCert},
		}

		transport := http.Transport{
			TLSClientConfig: &tlsConfig,
		}

		__client = &http.Client{
			Transport: &transport,
			Timeout:   time.Second * 5,
		}
	}

	return __client, nil
}

//
// Type mapping definitions for ReST communiation
// We are going to create a big structure to aid automatic identification of types
//

type IDP_Response struct {
	SimpleResponse  Simple_Response  `json:"Simple-Response"`
	IdentityProfile Identity_Profile `json:"Identity-Profile"`
	IntentReference Intent_Reference `json:"Intent-Reference"`
	ServiceIdentity Service_Identity `json:"Service-Identity"`
	http_code       int
}

type Simple_Response struct {
	Outcome string `json:"outcome"`
}

type Intent_Reference struct {
	Value   string `json:"value"`
	Outcome string `json:"outcome"`
}

type Identity_Profile struct {
	ServiceRoles       []string `json:"service-roles"`
	TrustSponsors      []string `json:"trust-sponsors"`
	SitesFrequented    int      `json:"sites-frequented"`
	AverageIdentityAge int      `json:"average-identity-age"`
	MaxIdentityAge     int      `json:"max-identity-age"`
	TrustScore         int      `json:"trust-score"`
	LocalTrust         int      `json:"local-trust"`
	LocalIntrusions    int      `json:"local-intrusions"`
	Outcome            string   `json:"outcome"`
}

type Service_Identity struct {
	P12         string `json:"p12"`
	Password    string `json:"password"`
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"private-key"`
	Outcome     string `json:"outcome"`
}

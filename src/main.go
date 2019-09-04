package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"runtime/debug"

	//"math/big"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// ---- Configuration ---------

type Load_Balancer struct {

	// values loaded from the config JSON
	Port             int      `json:"port"`
	AgentCertificate string   `json:"agent-certificate"`
	TrustStore       string   `json:"trust-store"`
	Workers          []Worker `json:"workers"`
	AgentKey         string   `json:"agent-key"`

	// values computed
	service_identity     Service_Identity
	Domain               string
	authorities          *x509.CertPool
	response_403         string
	response_404         string
	response_maintenance string
}

type Worker struct {
	Host         string `json:"host"`
	Port         int    `json:"port"`
	jobs_handled int
}

var load_balancer Load_Balancer

// ---- Request & Response Processing ---------

// Add response headers and sticky cookie
func post_process_response(preferred_worker int, res http.ResponseWriter) http.ResponseWriter {

	backend_index := strconv.Itoa(preferred_worker)
	expiration := time.Now().Add(365 * 24 * time.Hour)
	cookie := http.Cookie{Name: "x-lb-ray", Value: backend_index, Expires: expiration, Path: "/"}
	http.SetCookie(res, &cookie)

	return res
}

// add downstream headers
func pre_process_request(from *Client_Validation_Ticket, url *url.URL, req *http.Request) {
	// Update the headers to allow for SSL redirection
	req.URL.Host = url.Host
	req.URL.Scheme = url.Scheme
	req.Header.Set("X-Client-IP", req.RemoteAddr[0:strings.Index(req.RemoteAddr, ":")])

	// Populate the IDP headers with the certificate related information
	populate_request_headers(from, req)

	req.Host = url.Host
}

// Send the request to the given proxy backend
// as input we have the original request and the original response
func proxy_call(from *Client_Validation_Ticket, backend *Worker, res http.ResponseWriter, req *http.Request) {
	// parse the url
	downstream := "http://" + backend.Host + ":" + strconv.Itoa(backend.Port)
	url, _ := url.Parse(downstream)

	pre_process_request(from, url, req)

	// create the reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(url)

	// Note that ServeHttp is non blocking and uses a go routine under the hood
	proxy.ServeHTTP(res, req)
}

// detect backend load balancer based on cookie
func identify_preferred_backend(request *http.Request) int {
	for _, cookie := range request.Cookies() {
		if cookie.Name == "x-lb-ray" {
			i, err := strconv.Atoi(cookie.Value)

			if err != nil {
				return -1
			}

			return i
		}
	}

	// pick a load balancer and set the x-lb-ray sticky cookie
	return -1
}

// Given a request send it to the appropriate url
// this happens in the thread of the request as handled by the http handle function
func handle_request(res http.ResponseWriter, req *http.Request) {
	time_zero := time.Now()

	if req.URL.Path == "/reboot" {
		// trigger an identity load to reach out and fetch the new certificate if necessary
		// load_identity(false)

		res.WriteHeader(http.StatusOK)
		res.Header().Add("Connection", "close")

		reload_url := "https://" + load_balancer.Domain
		if load_balancer.Port != 443 {
			reload_url += ":" + strconv.Itoa(load_balancer.Port)
		}

		// the load balancer contains the new URL at this stage, so we will redirect
		res.Write([]byte(strings.Replace(load_balancer.response_maintenance, "${location}", reload_url, -1)))

		reboot(3)

		return
	}

	from, handled := validate_client_certificate(res, req)

	if !handled {
		// false means response was handled by the validate client certificate function
		return
	}

	// url, _ := url.Parse(req.)
	domain := req.Host
	idx := strings.Index(domain, ":")
	if idx > 0 {
		domain = domain[0:idx]
	}

	if load_balancer.Domain != domain {
		res.WriteHeader(http.StatusNotFound)
		res.Write([]byte(strings.Replace(load_balancer.response_404, "${reason}", "https://"+domain+req.URL.String(), -1)))
		return
	}

	// see if the client has a preference for a backend worker
	preferred_worker := identify_preferred_backend(req)

	// pick the worker with least jobs handled
	var worker *Worker

	if preferred_worker >= 0 && preferred_worker < len(load_balancer.Workers) {
		// there is a preferred worker and it exists
		worker = &load_balancer.Workers[preferred_worker]
	} else {
		// select the next least loaded worker
		worker = &load_balancer.Workers[0]
		preferred_worker = 0
		for _, w := range load_balancer.Workers {
			if w.jobs_handled < worker.jobs_handled {
				worker = &w
				preferred_worker++
			}
		}
	}

	// increase the job count for the worker and log the event
	worker.jobs_handled++

	// send the call to the backend
	proxy_call(from, worker, post_process_response(preferred_worker, res), req)

	log_request(from, req, worker, time_zero)

	go debug.FreeOSMemory()
}

// ----------------------------
// Main function
//
var server *http.Server

func main() {

	if !load_configuration() {

		log.Fatalf("Please address the missing configurations and try again")

	} else {

		// launch the renew daemon in parallel thread
		go renew_daemon()

		for true {

			// we do this only once then the
			key_stores, err := load_identity(false)

			if err != nil {
				fmt.Printf("Fatal Error ...\n%s\n", err.Error())
				return
			}

			// start server
			server = &http.Server{
				Addr:    ":" + strconv.Itoa(load_balancer.Port),
				Handler: http.HandlerFunc(handle_request),

				TLSConfig: &tls.Config{
					ClientAuth:   tls.RequestClientCert,
					RootCAs:      load_balancer.authorities,
					Certificates: key_stores,
				},
			}

			// server.HandleFunc("/", handle_request)
			if err := server.ListenAndServeTLS("", ""); err != nil {
				log.Printf("going down: %s\n", err.Error())
			}

			log.Printf("rebooting ...\n")
		}
	}
}

// ------------------------- Logging and Configurations --------------------------

func reboot(timeout time.Duration) {
	go func() {
		if timeout > 0 {
			time.Sleep(timeout * time.Second)
		}

		if err := server.Shutdown(context.Background()); err != nil {
			log.Fatal(err)
		}
	}()
}

// Log the typeform payload and redirect url
func log_request(from *Client_Validation_Ticket, req *http.Request, worker *Worker, time_zero time.Time) {
	log.Printf(
		"{client{id:%s, name:%s, ip:%s, roles:%s}, service{id:%s, ip:%s}, worker{ip:%s, port:%d}, uri:%s, size:%d, time:%f}\n",
		from.serial_no.String(), from.device_type+" / "+from.device_name, req.RemoteAddr, strings.Join(from.cache.ServiceRoles, ","),
		load_balancer.Domain, req.Host,
		worker.Host, worker.Port,
		req.URL.Path, 0, float64(time.Now().Sub(time_zero).Nanoseconds())/100000000)
}

func renew_daemon() {
	for true {
		time.Sleep(time.Minute)

		if renew_identity(false) {
			reboot(0)
		}
	}
}

func renew_identity(must_renew bool) bool {
	//defer func() {
	//	if v := recover(); v != nil {
	//		log.Printf("something went wrong during identity renew (%s), trying later ...\n", v)
	//	}
	//}()

	response := service_identity_renewal(must_renew)

	// if we receive identity. The server decided it was necessary to renew the certificate,
	// or the client explicitly requested it (there was no identity)
	if response.ServiceIdentity.Certificate != "" {
		// copy the data into the load balancer
		load_balancer.service_identity = response.ServiceIdentity

		// save the identity in the identity file
		json, _ := json.Marshal(load_balancer.service_identity)
		ioutil.WriteFile("server-identity.json", json, 0644)

		return true
	}

	return false
}

func load_identity(must_renew bool) ([]tls.Certificate, error) {

	jsonFile, err := os.Open("server-identity.json")

	// if an identity is found, the balancer will contain a service identity
	if err != nil {

		must_renew = true

	} else {

		// unmarshal the identity json into the load balancer
		byteValue, _ := ioutil.ReadAll(jsonFile)
		json.Unmarshal(byteValue, &load_balancer.service_identity)
		jsonFile.Close()
	}

	if must_renew {
		renew_identity(must_renew)
	}

	// we now load the DER encoded data into a keystore type
	key_store, err := load_keystore(load_balancer.service_identity)

	if err != nil {

		return nil, err

	} else {

		crt, err := x509.ParseCertificate(key_store.Certificate[0])
		if err != nil {
			return nil, err
		}

		load_balancer.Domain = crt.Subject.CommonName

		log.Printf("certified domain: %s\n", load_balancer.Domain)
		log.Printf("expires: %s (%.2f days)\n", crt.NotAfter, crt.NotAfter.Sub(time.Now()).Hours()/24)

		if crt.NotAfter.Sub(time.Now()).Hours()/24 < 40 {
			return load_identity(true)
		}

		return []tls.Certificate{*key_store}, nil
	}
}

func load_keystore(service_identity Service_Identity) (*tls.Certificate, error) {
	certificate_data, err := base64.StdEncoding.DecodeString(service_identity.Certificate)
	if err != nil {
		return nil, errors.New("Unable to Base64 decode the certificate. Identity JSON file may be corrupt: " + err.Error())
	}

	key_data, err := base64.StdEncoding.DecodeString(service_identity.PrivateKey)
	if err != nil {
		return nil, errors.New("Unable to Base64 decode the private key. Identity JSON file may be corrupt: " + err.Error())
	}

	key_store, err := tls.X509KeyPair(certificate_data, key_data)

	if err != nil {
		return nil, errors.New("Unable to load certificate. Certificate data may be corrupt: " + err.Error())
	}

	return &key_store, nil
}

// load configuration and log it
func load_configuration() bool {

	// load the configuration file
	jsonFile, err := os.Open("config.json")
	if err != nil {
		fmt.Println(err)
		return false
	}

	// unmarshal the json
	defer jsonFile.Close()
	byteValue, _ := ioutil.ReadAll(jsonFile)
	json.Unmarshal(byteValue, &load_balancer)

	idp_certs, err := ioutil.ReadFile(load_balancer.TrustStore)
	if err != nil {
		fmt.Println(err)
		return false
	}

	buf, err := ioutil.ReadFile("403.html")
	if err != nil {
		fmt.Println(err)
		return false
	}
	load_balancer.response_403 = string(buf)

	buf, err = ioutil.ReadFile("404.html")
	if err != nil {
		fmt.Println(err)
		return false
	}
	load_balancer.response_404 = string(buf)

	buf, err = ioutil.ReadFile("rebooting.html")
	if err != nil {
		fmt.Println(err)
		return false
	}
	load_balancer.response_maintenance = string(buf)

	// Log setup values
	load_balancer.authorities = x509.NewCertPool()
	load_balancer.authorities.AppendCertsFromPEM(idp_certs)

	log.Printf("client-authorities: %s\n", load_balancer.TrustStore)

	// for _, certificate := range load_balancer.authorities.certs {
	//     log.Printf("      ---> %s\n", certificate.Subject)
	// }

	for _, worker := range load_balancer.Workers {
		log.Printf("routing *:%d ---> %s\n", load_balancer.Port, worker.Host+":"+strconv.Itoa(worker.Port))
	}

	return true
}

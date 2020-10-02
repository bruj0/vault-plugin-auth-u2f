// FIDO U2F Go Library
// Copyright 2015 The FIDO U2F Go Library Authors. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package main

import (
	"crypto/tls"
	"encoding/json"
	"log"
	"net/http"

	"github.com/ryankurte/go-u2f"
)

const appID = "https://lxc1:3483"

var trustedFacets = []string{appID}

// Normally these state variables would be stored in a database.
// For the purposes of the demo, we just store them in memory.
var challenge *u2f.Challenge

var registrations []u2f.Registration

func registerRequest(w http.ResponseWriter, r *http.Request) {
	c, err := u2f.NewChallenge(appID, trustedFacets, registrations)
	if err != nil {
		log.Printf("u2f.NewChallenge error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	challenge = c
	req := c.RegisterRequest()

	log.Printf("1 registerRequest: %+v", req)
	json.NewEncoder(w).Encode(req)
}

func registerResponse(w http.ResponseWriter, r *http.Request) {
	var regResp u2f.RegisterResponse
	if err := json.NewDecoder(r.Body).Decode(&regResp); err != nil {
		http.Error(w, "invalid response: "+err.Error(), http.StatusBadRequest)
		return
	}

	if challenge == nil {
		http.Error(w, "challenge not found", http.StatusBadRequest)
		return
	}

	reg, err := challenge.Register(regResp, &u2f.RegistrationConfig{SkipAttestationVerify: true})
	if err != nil {
		log.Printf("u2f.Register error: %v", err)
		http.Error(w, "error verifying response", http.StatusInternalServerError)
		return
	}

	registrations = append(registrations, *reg)

	log.Printf("Registration success: %+v", reg)
	w.Write([]byte("success"))
}

func signRequest(w http.ResponseWriter, r *http.Request) {
	if registrations == nil {
		http.Error(w, "registrations missing", http.StatusBadRequest)
		return
	}

	c, err := u2f.NewChallenge(appID, trustedFacets, registrations)
	if err != nil {
		log.Printf("u2f.NewChallenge error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	challenge = c

	req := c.SignRequest()

	log.Printf("authenticateRequest: %+v", req)
	json.NewEncoder(w).Encode(req)
}

func signResponse(w http.ResponseWriter, r *http.Request) {
	var signResp u2f.SignResponse
	if err := json.NewDecoder(r.Body).Decode(&signResp); err != nil {
		http.Error(w, "invalid response: "+err.Error(), http.StatusBadRequest)
		return
	}

	log.Printf("signResponse: %+v", signResp)

	if challenge == nil {
		http.Error(w, "challenge missing", http.StatusBadRequest)
		return
	}
	if registrations == nil {
		http.Error(w, "registrations missing", http.StatusBadRequest)
		return
	}

	reg, err := challenge.Authenticate(signResp)
	if err == nil {
		log.Printf("newCounter: %d", reg.Counter)
		w.Write([]byte("success"))
		return
	}

	log.Printf("VerifySignResponse error: %v", err)
	http.Error(w, "error verifying response", http.StatusInternalServerError)
}

const indexHTML = `
<!DOCTYPE html>
<html>
  <head>
    <script src="//code.jquery.com/jquery-1.11.2.min.js"></script>

    <!-- The original u2f-api.js code can be found here:
    https://github.com/google/u2f-ref-code/blob/master/u2f-gae-demo/war/js/u2f-api.js -->
    <script type="text/javascript" src="js/u2f-api.js"></script>

  </head>
  <body>
    <h1>FIDO U2F Go Library Demo</h1>

    <ul>
      <li><a href="javascript:register();">Register token</a></li>
      <li><a href="javascript:sign();">Authenticate</a></li>
    </ul>

    <script>
  function u2fRegistered(resp) {
    console.log(resp);
    $.post('/registerResponse', JSON.stringify(resp)).done(function() {
      alert('Success');
    });
  }

  function register() {
    $.getJSON('/registerRequest').done(function(req) {
      console.log("Registration request:")
      console.log(req);
	  u2f.register(req.appId, req.registerRequests, req.registeredKeys, u2fRegistered, 60);
	 console.log(req);
    });
  }

  function u2fSigned(resp) {
    console.log(resp);
    console.log("Sign response:")

    $.post('/signResponse', JSON.stringify(resp)).done(function() {
        alert('Success');
    });
  }

  function sign() {
    $.getJSON('/signRequest').done(function(req) {
	  console.log("Sign request:")
      console.log(req);
	  u2f.sign(req.appId, req.challenge, req.registeredKeys, u2fSigned, 60);
    });
  }

    </script>

  </body>
</html>
`

func indexHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(indexHTML))
}

func main() {

	registrations = append(registrations, u2f.Registration{
		KeyHandle:   "zmhmbCp9f6GEItHLSBrKIxXB26XnbPjhls2wW32xbM7exZQxMOvX_fqlaC7OWuCf3qRecXdR8dItVMCCDFRWUg",
		PublicKey:   "BFm2_zwxlS9Nzf-57Uoy9rL_w4kYWE7tobUX3W1NxJhzkA3hpFhvju3p4VX0_rftKdYdRZqXIJRHuH1PTS3ygv4",
		Counter:     0,
		Certificate: "MIIBNTCB3KADAgECAgsAwAyhO3AYD-SngjAKBggqhkjOPQQDAjAVMRMwEQYDVQQDEwpVMkYgSXNzdWVyMBoXCzAwMDEwMTAwMDBaFwswMDAxMDEwMDAwWjAVMRMwEQYDVQQDEwpVMkYgRGV2aWNlMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEVt5r4IIBihiZDFD_GN-gAtQJEo0pGcnKFuDtirT4KKycCxOZzvDzEIhosWczhet8Texz0WD69sTZBEQe-GUEjKMXMBUwEwYLKwYBBAGC5RwCAQEEBAMCBSAwCgYIKoZIzj0EAwIDSAAwRQIhAMGjpo4vFqchRicFf2K7coyeA-ehumLQRlJORW0sLz9zAiALX3jlEaoYEp9vI22SEyJ9krTmft9T6BbfsF2dyLkP3g",
	})

	http.Handle("/js/", http.StripPrefix("/js/", http.FileServer(http.Dir("./js"))))
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/registerRequest", registerRequest)
	http.HandleFunc("/registerResponse", registerResponse)
	http.HandleFunc("/signRequest", signRequest)
	http.HandleFunc("/signResponse", signResponse)

	certs, err := tls.X509KeyPair([]byte(tlsCert), []byte(tlsKey))
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Running on %s", appID)

	var s http.Server
	s.Addr = ":3483"
	s.TLSConfig = &tls.Config{Certificates: []tls.Certificate{certs}}
	log.Fatal(s.ListenAndServeTLS("", ""))
}

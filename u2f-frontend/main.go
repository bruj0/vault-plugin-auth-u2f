// FIDO U2F Go Library
// Copyright 2015 The FIDO U2F Go Library Authors. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/ryankurte/go-u2f"
)

const appID = "https://localhost:3483"

var trustedFacets = []string{appID}

// Normally these state variables would be stored in a database.
// For the purposes of the demo, we just store them in memory.
var challenge *u2f.Challenge

var registrations []u2f.Registration

func registerRequest(w http.ResponseWriter, r *http.Request) {
	// c, err := u2f.NewChallenge(appID, trustedFacets, registrations)
	// if err != nil {
	// 	log.Printf("u2f.NewChallenge error: %v", err)
	// 	http.Error(w, "error", http.StatusInternalServerError)
	// 	return
	// }
	// challenge = c
	// req := c.RegisterRequest()

	//json.NewEncoder(w).Encode(req)
	dataJSON := "{ \"role_name\": \"my-role\"}"
	req, statusCode := postPasstrough("auth/u2f/registerRequest/mydevice", []byte(dataJSON))
	if statusCode != 200 {
		log.Printf("registerRequest code %d , error: %v", statusCode, req)
		http.Error(w, "registerRequest response", statusCode)
	}
	log.Printf("1 registerRequest: %s", req)
	w.Write([]byte(req))

}

func registerResponse(w http.ResponseWriter, r *http.Request) {
	var regResp u2f.RegisterResponse

	// body, err := ioutil.ReadAll(r.Body)
	// if err != nil {
	// 	fmt.Printf(err.Error())
	// 	return
	// }
	// log.Printf("registerResponse body: %s", body)

	if err := json.NewDecoder(r.Body).Decode(&regResp); err != nil {
		log.Printf("registerResponse error: %s", err.Error())
		http.Error(w, "invalid response: "+err.Error(), http.StatusBadRequest)
		return
	}

	log.Printf("registerResponse regResp: %v", regResp)
	dataJSON, err := json.Marshal(struct {
		ClientData       string `json:"clientData"`
		RegistrationData string `json:"registrationData"`
		Name             string `json:"name"`
	}{
		regResp.ClientData,
		regResp.RegistrationData,
		"mydevice",
	})
	if err != nil {
		fmt.Println(err)
		return
	}

	req, statusCode := postPasstrough("auth/u2f/registerResponse/mydevice", dataJSON)
	if statusCode != 200 {
		log.Printf("registerResponse code %d , error: %v", statusCode, req)
		http.Error(w, "error verifying response", statusCode)
	}
	log.Printf("Registration success")
	w.Write([]byte(req))
}

func signRequest(w http.ResponseWriter, r *http.Request) {
	req, err := getPasstrough("auth/u2f/signRequest/mydevice")
	if err != 200 {
		log.Printf("signRequest error: %s, code %d", req, err)
		http.Error(w, "invalid response: "+req, err)
	}
	log.Printf("1 signRequest: %s", req)
	w.Write([]byte(req))
}

func signResponse(w http.ResponseWriter, r *http.Request) {

	var signResp u2f.SignResponse
	if err := json.NewDecoder(r.Body).Decode(&signResp); err != nil {
		http.Error(w, "invalid response: "+err.Error(), http.StatusBadRequest)
		return
	}

	log.Printf("signResponse: %+v", signResp)

	dataJSON, err := json.Marshal(struct {
		KeyHandle     string `json:"keyHandle"`
		SignatureData string `json:"signatureData"`
		ClientData    string `json:"clientData"`
		Name          string `json:"name"`
	}{
		signResp.KeyHandle,
		signResp.SignatureData,
		signResp.ClientData,
		"mydevice",
	})
	if err != nil {
		fmt.Println(err)
		http.Error(w, "invalid response: "+err.Error(), http.StatusBadRequest)
		return
	}
	req, statusCode := postPasstrough("auth/u2f/signResponse/mydevice", dataJSON)
	if statusCode != 200 {
		log.Printf("registerResponse code %d , error: %v", statusCode, req)
		http.Error(w, "error verifying response", statusCode)
	}
	log.Printf("Authentication success")
	w.Write([]byte(req))
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
    <h1>Frontend Demo for the U2F authentication plugin for Vault</h1>

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
    console.log("Sign response:")
    console.log(resp);
    $.post('/signResponse', JSON.stringify(resp)).done(function(ret) {
		console.log("u2fSigned:")
		var data=JSON.parse(ret)
		console.log(data)
		console.log("Your token is: "+data.auth.client_token)
        alert('Success, token: ' + data.auth.client_token);
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

const (
	vaultAddr = "http://localhost:8200"

	staticToken = "root"
)

var client *http.Client

func getPasstrough(url string) (string, int) {
	req, err := http.NewRequest("GET", vaultAddr+"/v1/"+url, nil)
	if err != nil {
		fmt.Printf(err.Error())
		return err.Error(), http.StatusInternalServerError
	}
	req.Header.Add("X-Vault-Token", staticToken)
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf(err.Error())
		return err.Error(), http.StatusInternalServerError
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf(err.Error())
		return err.Error(), http.StatusInternalServerError
	}

	return string(body), resp.StatusCode

}
func postPasstrough(url string, data []byte) (string, int) {
	fmt.Printf("postPasstrough data: %s\n", data)
	req, err := http.NewRequest("POST", vaultAddr+"/v1/"+url, bytes.NewBuffer(data))
	if err != nil {
		fmt.Printf(err.Error())
		return err.Error(), http.StatusInternalServerError
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Add("X-Vault-Token", staticToken)

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf(err.Error())
		return err.Error(), http.StatusInternalServerError
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf(err.Error())
		return err.Error(), http.StatusInternalServerError
	}
	fmt.Printf("postPasstrough returned: %s\n", body)
	return string(body), resp.StatusCode
}
func main() {
	client = &http.Client{}
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

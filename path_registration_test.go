package u2fauth

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/davecgh/go-spew/spew"
	log "github.com/hashicorp/go-hclog"

	"github.com/hashicorp/vault/sdk/helper/logging"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/ryankurte/go-u2f"
)

func getBackend(t *testing.T) (logical.Backend, logical.Storage) {
	config := &logical.BackendConfig{
		Logger:      logging.NewVaultLogger(log.Trace),
		System:      &logical.StaticSystemView{},
		StorageView: &logical.InmemStorage{},
		BackendUUID: "test",
	}

	b, err := Factory(context.Background(), config)
	if err != nil {
		t.Fatalf("unable to create backend: %v", err)
	}

	// Wait for the upgrade to finish
	time.Sleep(time.Second)

	return b, config.StorageView
}

var app_id string = "http://localhost"
var registrations []u2f.Registration

func TestRegistrationRequest(t *testing.T) {
	b, storage := getBackend(t)

	createRole(t, b, storage, "role1", "c,d")
	//Generate challenge by calling registerRequest
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "registerRequest/my-device",
		Storage:   storage,
		Data: map[string]interface{}{
			"role_name": "my-role",
		},
	}

	// Generate registration request
	resp, err := b.HandleRequest(context.Background(), req)
	if err == nil || resp != nil {
		t.Fatalf("err:%s resp:%#v isError=%t\n", err, resp, resp.IsError())
	}

}
func TestE2ERequests(t *testing.T) {
	b, storage := getBackend(t)

	vk, err := u2f.NewVirtualKey()
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	createRole(t, b, storage, "my-role", "c,d")
	//Generate challenge by calling registerRequest
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "registerRequest/my-device",
		Storage:   storage,
		Data: map[string]interface{}{
			"role_name": "my-role",
		},
	}

	// Generate registration request
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	t.Log("registerRequest resp", spew.Sdump(resp))
	t.Log("registerRequest http_raw_body", resp.Data["http_raw_body"])

	//Convert it to RegisterRequestMessage
	var registerReq u2f.RegisterRequestMessage
	rawBody := bytes.NewBufferString(resp.Data["http_raw_body"].(string))
	dec := json.NewDecoder(rawBody)
	err = dec.Decode(&registerReq)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	t.Log("registerReq", spew.Sdump(registerReq))

	// Pass to virtual token
	vKresp, err := vk.HandleRegisterRequest(registerReq)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	t.Log("vKresp", spew.Sdump(vKresp))
	//Register the token by calling registerResponse
	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "registerResponse/my-device",
		Storage:   storage,
		Data: map[string]interface{}{
			"registrationData": vKresp.RegistrationData,
			"clientData":       vKresp.ClientData,
		},
	}

	// Generate registration request
	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}
	t.Log("RegistrationResponse", spew.Sdump(resp))

	//Generate challenge by calling signRequest
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "signRequest/my-device",
		Storage:   storage,
	}

	// Generate registration request
	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	t.Log("signRequest resp", spew.Sdump(resp))
	t.Log("registerRequest http_raw_body", resp.Data["http_raw_body"])

	//Convert it to SignRequestMessage
	var signReq u2f.SignRequestMessage
	rawBody = bytes.NewBufferString(resp.Data["http_raw_body"].(string))
	dec = json.NewDecoder(rawBody)
	err = dec.Decode(&signReq)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	t.Log("SignRequestMessage: signReq", spew.Sdump(signReq))

	// Pass to virtual token
	signResp, err := vk.HandleAuthenticationRequest(signReq)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	t.Log("SignRequestMessage: signResp", spew.Sdump(signResp))

	//Authenticate by calling signResponse
	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "signResponse/my-device",
		Storage:   storage,
		Data: map[string]interface{}{
			"keyHandle":     signResp.KeyHandle,
			"signatureData": signResp.SignatureData,
			"clientData":    signResp.ClientData,
		},
	}
	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	t.Log("signRequest resp", spew.Sdump(resp))

}

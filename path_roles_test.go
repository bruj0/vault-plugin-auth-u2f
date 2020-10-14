package u2fauth

import (
	"context"
	"testing"

	"reflect"

	"github.com/davecgh/go-spew/spew"
	"github.com/hashicorp/vault/sdk/helper/policyutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/mitchellh/mapstructure"
)

func Test_RolesCRUD(t *testing.T) {
	b, storage := getBackend(t)

	//Generate challenge by calling registerRequest
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/my-role",
		Storage:   storage,
		Data: map[string]interface{}{
			"name":              []string{"my-role"},
			"token_policies":    []string{"p", "q", "r", "s"},
			"token_ttl":         400,
			"token_max_ttl":     500,
			"token_bound_cidrs": []string{"127.0.0.1", "127.0.0.2"},
		},
	}
	// Generate registration request
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	t.Log("registerRequest resp", spew.Sdump(resp))

	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "roles/my-role",
		Storage:   storage,
	}
	// Generate registration request
	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}
	t.Logf("resp:%s", spew.Sdump(resp))

	expected := map[string]interface{}{
		"name":              "my-policy",
		"token_policies":    []string{"p", "q", "r", "s"},
		"token_ttl":         400,
		"token_max_ttl":     500,
		"token_num_uses":    600,
		"token_bound_cidrs": []string{"127.0.0.1/32", "127.0.0.1/16"},
		"token_type":        "default",
	}

	var expectedStruct RoleEntry
	err = mapstructure.Decode(expected, &expectedStruct)
	if err != nil {
		t.Fatal(err)
	}

	var actualStruct RoleEntry
	err = mapstructure.Decode(resp.Data, &actualStruct)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(expectedStruct, actualStruct) {
		t.Fatalf("bad:\nexpected:%#v\nactual:%#v\n", expectedStruct, actualStruct)
	}

	t.Logf("bad:\nexpected:%#v\nactual:%#v\n", expectedStruct, actualStruct)

}
func createRole(t *testing.T, b logical.Backend, s logical.Storage, roleName, policies string) {
	roleData := map[string]interface{}{
		"token_policies": policies,
		"token_ttl":      400,
		"token_max_ttl":  500,
	}
	roleReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/" + roleName,
		Storage:   s,
		Data:      roleData,
	}

	resp, err := b.HandleRequest(context.Background(), roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}
}

func Test_RoleList(t *testing.T) {
	var resp *logical.Response
	var err error
	b, storage := getBackend(t)

	createRole(t, b, storage, "role1", "a,b")
	createRole(t, b, storage, "role2", "c,d")
	createRole(t, b, storage, "role3", "e,f")
	createRole(t, b, storage, "role4", "g,h")
	createRole(t, b, storage, "role5", "i,j")

	listReq := &logical.Request{
		Operation: logical.ListOperation,
		Path:      "roles",
		Storage:   storage,
	}
	resp, err = b.HandleRequest(context.Background(), listReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	actual := resp.Data["keys"].([]string)
	expected := []string{"role1", "role2", "role3", "role4", "role5"}
	if !policyutil.EquivalentPolicies(actual, expected) {
		t.Fatalf("bad: listed roles: expected:%s\nactual:%s", expected, actual)
	}
}

func TestAppRole_RoleUpdate(t *testing.T) {
	var resp *logical.Response
	var err error
	b, storage := getBackend(t)

	roleData := map[string]interface{}{
		"name":              "my-policy",
		"token_policies":    []string{"p", "q", "r", "s"},
		"token_ttl":         400,
		"token_max_ttl":     500,
		"token_num_uses":    600,
		"token_bound_cidrs": []string{"127.0.0.1/32", "127.0.0.1/16"},
		"token_type":        "default",
	}
	roleReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/testrole1",
		Storage:   storage,
		Data:      roleData,
	}
	resp, err = b.HandleRequest(context.Background(), roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	roleUpdateReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/testrole1",
		Storage:   storage,
		Data: map[string]interface{}{
		"name":              "my-policy",
		"token_policies":    []string{"a", "b", "c", "d"},
		"token_ttl":         400,
		"token_max_ttl":     500,
		"token_num_uses":    600,
		"token_bound_cidrs": []string{"127.0.0.1/32", "127.0.0.1/16"},
		"token_type":        "default",
		},
	}
	resp, err = b.HandleRequest(context.Background(), roleUpdateReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "roles/testrole1",
		Storage:   storage,
	}
	// Generate registration request
	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}
	t.Logf("resp:%s", spew.Sdump(resp.Data))

	expected := map[string]interface{}{
		"name":              "my-policy",
		"token_policies":    []string{"a", "b", "c", "d"},
		"token_ttl":         400,
		"token_max_ttl":     500,
		"token_num_uses":    600,
		"token_bound_cidrs": []string{"127.0.0.1/32", "127.0.0.1/16"},
		"token_type": logical.TokenTypeDefault,

	}

	var expectedStruct RoleEntry
	err = mapstructure.Decode(expected, &expectedStruct)
	if err != nil {
		t.Fatal(err)
	}
	expectedStruct.PopulateTokenData(expected)
	t.Logf("expectedStruct:%s", spew.Sdump(expectedStruct))

	var actualStruct RoleEntry
	resp.Data["token_type"]=logical.TokenTypeDefault
	err = mapstructure.Decode(resp.Data, &actualStruct)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("actualStruct:%s", spew.Sdump(actualStruct))

	if !reflect.DeepEqual(expectedStruct, actualStruct) {
		t.Fatalf("bad:\nexpected:%#v\nactual:%#v\n", expectedStruct, actualStruct)
	}
}

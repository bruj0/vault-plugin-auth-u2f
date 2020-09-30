package u2fauth

import (
	"context"
	"fmt"
	"reflect"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// Factory returns a configured instance of the backend.
func Factory(ctx context.Context, c *logical.BackendConfig) (logical.Backend, error) {
	b := Backend()
	if err := b.Setup(ctx, c); err != nil {
		return nil, err
	}
	return b, nil
}

func Backend() *backend {
	var b backend
	b.Backend = &framework.Backend{
		BackendType: logical.TypeCredential,
		AuthRenew:   b.pathLoginRenew,
		Help:        backendHelp,
		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{
				"login/*",
			},
		},
		Paths: append([]*framework.Path{
			pathDevices(&b),
			pathLogin(&b),
		}),
	}

	return &b
}

type backend struct {
	*framework.Backend
}

const backendHelp = `
The "u2f" credential provider allows authentication using
a u2f enabled device. No additional factors are supported.

The device  is configured using the "device/"
endpoints by a user with root access. Authentication is then done
by suppying the fields for "login".
`

func (b *backend) updateRegistrationData(req *logical.Request, d *framework.FieldData, dEntry *U2fEntry) (error, error) {
	return b.updateData(req, d, dEntry, "registrationData")
}
func (b *backend) updateClientData(req *logical.Request, d *framework.FieldData, dEntry *U2fEntry) (error, error) {
	return b.updateData(req, d, dEntry, "clientData")
}
func (b *backend) updateChallenge(req *logical.Request, d *framework.FieldData, dEntry *U2fEntry) (error, error) {
	return b.updateData(req, d, dEntry, "challenge")
}
func (b *backend) updateVersion(req *logical.Request, d *framework.FieldData, dEntry *U2fEntry) (error, error) {
	return b.updateData(req, d, dEntry, "version")
}
func (b *backend) updateData(req *logical.Request, d *framework.FieldData, dEntry *U2fEntry, field string) (error, error) {
	fieldRaw := d.Get(field).(string)
	if fieldRaw == "" {
		return fmt.Errorf(fmt.Sprintf("missing %s", field)), nil
	}
	reflect.ValueOf(dEntry).Elem().FieldByName(field).SetString(fieldRaw)
	return nil, nil
}

func (b *backend) device(ctx context.Context, s logical.Storage, name string) (*U2fEntry, error) {
	if name == "" {
		return nil, fmt.Errorf("missing name")
	}

	entry, err := s.Get(ctx, "devices/"+strings.ToLower(name))
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var result U2fEntry
	if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}
	if result.TokenTTL == 0 && result.TTL > 0 {
		result.TokenTTL = result.TTL
	}
	if result.TokenMaxTTL == 0 && result.MaxTTL > 0 {
		result.TokenMaxTTL = result.MaxTTL
	}
	if len(result.TokenPolicies) == 0 && len(result.Policies) > 0 {
		result.TokenPolicies = result.Policies
	}

	return &result, nil
}

func (b *backend) setDevice(ctx context.Context, s logical.Storage, name string, u2fEntry *U2fEntry) error {
	entry, err := logical.StorageEntryJSON("device/"+name, u2fEntry)
	if err != nil {
		return err
	}

	return s.Put(ctx, entry)
}

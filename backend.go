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
				//"registrationRequest",
			},
		},
		Paths: append([]*framework.Path{
			pathDevices(&b),
			pathDevicesList(&b),
			pathLogin(&b),
			pathRegistrationRequest(&b),
			pathRegistrationResponse(&b),
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

func (b *backend) updateRegistrationData(req *logical.Request, d *framework.FieldData, dEntry *DeviceData) (error, error) {
	return b.updateData(req, d, dEntry, "registration_data", "RegistrationData")
}
func (b *backend) updateClientData(req *logical.Request, d *framework.FieldData, dEntry *DeviceData) (error, error) {
	return b.updateData(req, d, dEntry, "client_data", "ClientData")
}
func (b *backend) updateVersion(req *logical.Request, d *framework.FieldData, dEntry *DeviceData) (error, error) {
	return b.updateData(req, d, dEntry, "version", "Version")
}
func (b *backend) updateData(req *logical.Request, d *framework.FieldData, dEntry *DeviceData, field string, structField string) (error, error) {
	fieldValue := d.Get(field).(string)
	if structField == "" {
		structField = field
	}
	b.Logger().Debug("updateData", "fieldValue", fieldValue, "structField", structField)
	reflect.ValueOf(dEntry).Elem().FieldByName(structField).SetString(fieldValue)
	return nil, nil
}

func (b *backend) device(ctx context.Context, s logical.Storage, name string) (*DeviceData, error) {
	if name == "" {
		return nil, fmt.Errorf("missing name")
	}

	entry, err := s.Get(ctx, "devices/"+strings.ToLower(name))
	b.Logger().Debug("device", "entry", entry)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var result DeviceData
	if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}
	b.Logger().Debug("device", "result", result)

	return &result, nil
}

func (b *backend) setDevice(ctx context.Context, s logical.Storage, name string, dEntry *DeviceData) error {
	entry, err := logical.StorageEntryJSON("devices/"+name, dEntry)
	b.Logger().Debug("setDevice", "entry", entry)
	if err != nil {
		return err
	}

	return s.Put(ctx, entry)
}

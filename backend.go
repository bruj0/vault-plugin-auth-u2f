package u2fauth

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/ryankurte/go-u2f"
)

const appID = "https://lxc1:3483"

var trustedFacets = []string{appID}

type DeviceData struct {
	Name string `json:"name" mapstructure:"name" structs:"name"`

	RegistrationData string `json:"registration_data"`

	ClientData string `json:"client_data"`

	Version string `json:"version"`

	AppID string `json:app_id`

	Registration []u2f.Registration `json:"registration"`

	Challenge *u2f.Challenge `json: challenge`

	RoleName string `json:"role_name"`
}

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
		//AuthRenew:   b.pathLoginRenew,
		Help: backendHelp,
		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{
				"signRequest/*",
				"signResponse/*",
			},
		},
		Paths: append([]*framework.Path{
			pathRoles(&b),
			pathRolesList(&b),
			pathRegistrationRequest(&b),
			pathRegistrationResponse(&b),
			pathSignRequest(&b),
			pathSignResponse(&b),
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

The device  is configured using the "device/" and "roles/"
endpoints by a user with the correct access.
 Authentication is then done by suppying the fields for "requestSign" and "responseSign" endpoints.
`

func (b *backend) device(ctx context.Context, s logical.Storage, name string) (*DeviceData, error) {
	if name == "" {
		return nil, fmt.Errorf("missing name")
	}

	entry, err := s.Get(ctx, "devices/"+strings.ToLower(name))
	//b.Logger().Debug("device", "entry", entry)
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
	//b.Logger().Debug("device", "result", result)

	return &result, nil
}

func (b *backend) setDevice(ctx context.Context, s logical.Storage, name string, dEntry *DeviceData) error {
	entry, err := logical.StorageEntryJSON("devices/"+name, dEntry)
	//b.Logger().Debug("setDevice", "entry", entry)
	if err != nil {
		return err
	}

	return s.Put(ctx, entry)
}

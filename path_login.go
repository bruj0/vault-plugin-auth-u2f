package u2fauth

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/policyutil"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathLogin(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "login/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"registrationData": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "registrationData of the device.",
			},

			"clientData": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "clientData for this device.",
			},
			"challenge": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "challenge for this device.",
			},
			"version": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "version for this device.",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation:         b.pathLogin,
			logical.AliasLookaheadOperation: b.pathLoginAliasLookahead,
		},

		HelpSynopsis:    pathLoginSyn,
		HelpDescription: pathLoginDesc,
	}
}
func (b *backend) pathLoginAliasLookahead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	device := strings.ToLower(d.Get("name").(string))
	if device == "" {
		return nil, fmt.Errorf("missing device name")
	}

	return &logical.Response{
		Auth: &logical.Auth{
			Alias: &logical.Alias{
				Name: device,
			},
		},
	}, nil
}
func (b *backend) pathLogin(
	ctx context.Context,
	req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	deviceName := strings.ToLower(d.Get("name").(string))

	// Get the device and validate auth
	device, err := b.device(ctx, req.Storage, deviceName)
	if err != nil {
		return nil, err
	}
	if device == nil {
		return logical.ErrorResponse("invalid device name or authentication"), nil
	}

	auth := &logical.Auth{
		Metadata: map[string]string{
			"name": deviceName,
		},
		DisplayName: deviceName,
		Alias: &logical.Alias{
			Name: deviceName,
		},
	}
	device.PopulateTokenAuth(auth)

	return &logical.Response{
		Auth: auth,
	}, nil
}

func (b *backend) pathLoginRenew(
	ctx context.Context,
	req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// Get the device
	device, err := b.device(ctx, req.Storage, req.Auth.Metadata["name"])
	if err != nil {
		return nil, err
	}
	if device == nil {
		// Device no longer exists, do not renew
		return nil, nil
	}

	if !policyutil.EquivalentPolicies(device.Policies, req.Auth.Policies) {
		return nil, fmt.Errorf("policies have changed, not renewing")
	}

	resp := &logical.Response{Auth: req.Auth}
	resp.Auth.Period = device.TokenPeriod
	resp.Auth.TTL = device.TokenTTL
	resp.Auth.MaxTTL = device.TokenMaxTTL
	return resp, nil
}

const pathLoginSyn = `
Log in with a u2f device.
`

const pathLoginDesc = `
This endpoint authenticates using a u2f device.
`

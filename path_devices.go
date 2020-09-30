package u2fauth

import (
	"context"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/tokenutil"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathUsersList(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "devices/?",

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ListOperation: b.pathDeviceList,
		},

		HelpSynopsis:    pathUserHelpSyn,
		HelpDescription: pathUserHelpDesc,
	}
}

func pathDevices(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "devices/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "User friendly name for this device.",
			},
			"registrationData": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "registrationData for this device.",
			},
			"challenge": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "challenge for this device.",
			},
			"version": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "registrationData this device.",
			},
			"clientData": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "clientData for this device.",
			},

			"policies": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Comma-separated list of policies",
			},
			"ttl": &framework.FieldSchema{
				Type:        framework.TypeString,
				Default:     "",
				Description: "The lease duration which decides login expiration",
			},
			"max_ttl": &framework.FieldSchema{
				Type:        framework.TypeString,
				Default:     "",
				Description: "Maximum duration after which login should expire",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.DeleteOperation: b.pathDeviceDelete,
			logical.ReadOperation:   b.pathDeviceRead,
			logical.UpdateOperation: b.pathDeviceWrite,
			logical.CreateOperation: b.pathDeviceWrite,
		},

		ExistenceCheck: b.ExistenceCheck,

		HelpSynopsis:    pathUserHelpSyn,
		HelpDescription: pathUserHelpDesc,
	}
}
func (b *backend) ExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	entry, err := b.device(ctx, req.Storage, data.Get("name").(string))
	if err != nil {
		return false, err
	}

	return entry != nil, nil
}

func (b *backend) pathDeviceList(
	ctx context.Context,
	req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	devices, err := req.Storage.List(ctx, "device/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(devices), nil
}

func (b *backend) pathDeviceDelete(
	ctx context.Context,
	req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, "device/"+strings.ToLower(d.Get("name").(string)))
	if err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) pathDeviceRead(
	ctx context.Context,
	req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	device, err := b.device(ctx, req.Storage, strings.ToLower(d.Get("name").(string)))
	if err != nil {
		return nil, err
	}
	if device == nil {
		return nil, nil
	}

	data := map[string]interface{}{}
	device.PopulateTokenData(data)

	return &logical.Response{
		// Data: map[string]interface{}{
		// 	"registrationData": device.RegistrationData,
		// 	"clientData":       device.ClientData,
		// 	"challenge":        device.Challenge,
		// 	"version":          device.Version,
		// 	"policies":         strings.Join(device.Policies, ","),
		// 	"ttl":              device.TTL.Seconds(),
		// 	"max_ttl":          device.MaxTTL.Seconds(),
		// },
		Data: data,
	}, nil
}

func (b *backend) deviceCreateUpdate(
	ctx context.Context,
	req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := strings.ToLower(d.Get("device").(string))
	dEntry, err := b.device(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	// Due to existence check, user will only be nil if it's a create operation
	if dEntry == nil {
		dEntry = &U2fEntry{}
	}
	if err := dEntry.ParseTokenFields(req, d); err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}

	if _, ok := d.GetOk("registrationData"); ok {
		dErr, intErr := b.updateRegistrationData(req, d, dEntry)
		if intErr != nil {
			return nil, err
		}
		if dErr != nil {
			return logical.ErrorResponse(dErr.Error()), logical.ErrInvalidRequest
		}
	}

	if _, ok := d.GetOk("clientData"); ok {
		dErr, intErr := b.updateClientData(req, d, dEntry)
		if intErr != nil {
			return nil, err
		}
		if dErr != nil {
			return logical.ErrorResponse(dErr.Error()), logical.ErrInvalidRequest
		}
	}

	if _, ok := d.GetOk("challenge"); ok {
		dErr, intErr := b.updateChallenge(req, d, dEntry)
		if intErr != nil {
			return nil, err
		}
		if dErr != nil {
			return logical.ErrorResponse(dErr.Error()), logical.ErrInvalidRequest
		}
	}

	if _, ok := d.GetOk("version"); ok {
		dErr, intErr := b.updateVersion(req, d, dEntry)
		if intErr != nil {
			return nil, err
		}
		if dErr != nil {
			return logical.ErrorResponse(dErr.Error()), logical.ErrInvalidRequest
		}
	}

	// handle upgrade cases
	{
		if err := tokenutil.UpgradeValue(d, "policies", "token_policies", &dEntry.Policies, &dEntry.TokenPolicies); err != nil {
			return logical.ErrorResponse(err.Error()), nil
		}

		if err := tokenutil.UpgradeValue(d, "ttl", "token_ttl", &dEntry.TTL, &dEntry.TokenTTL); err != nil {
			return logical.ErrorResponse(err.Error()), nil
		}

		if err := tokenutil.UpgradeValue(d, "max_ttl", "token_max_ttl", &dEntry.MaxTTL, &dEntry.TokenMaxTTL); err != nil {
			return logical.ErrorResponse(err.Error()), nil
		}
	}

	return nil, b.setDevice(ctx, req.Storage, name, dEntry)
}

func (b *backend) pathDeviceWrite(
	ctx context.Context,
	req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	registrationData := d.Get("registrationData").(string)
	if req.Operation == logical.CreateOperation && registrationData == "" {
		return logical.ErrorResponse("missing registrationData"), logical.ErrInvalidRequest
	}
	return b.deviceCreateUpdate(ctx, req, d)
}

type U2fEntry struct {
	tokenutil.TokenParams
	//Userfriendly name of the device
	Name string

	RegistrationData string

	ClientData string

	Challenge string

	Version string

	Policies []string

	// Duration after which the user will be revoked unless renewed
	TTL time.Duration

	// Maximum duration for which user can be valid
	MaxTTL time.Duration
}

const pathUserHelpSyn = `
Manage u2f devices allowed to authenticate.
`

const pathUserHelpDesc = `
This endpoint allows you to create, read, update, and delete u2f devices
that are allowed to authenticate.

Deleting a device will not revoke auth for prior authenticated devices
with that name. To do this, do a revoke on "device/<name>" for
the name you want revoked. If you don't need to revoke login immediately,
then the next renew will cause the lease to expire.
`

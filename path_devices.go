package u2fauth

import (
	"context"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/tokenutil"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathDevicesList(b *backend) *framework.Path {
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
			"registration_data": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "registration data for this device.",
			},
			"challenge": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "challenge for this device.",
			},
			"version": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "version of this device.",
			},
			"client_data": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "client data for this device.",
			},

			"token_policies": &framework.FieldSchema{
				Type:        framework.TypeCommaStringSlice,
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
			"token_bound_cidrs": &framework.FieldSchema{
				Type:        framework.TypeCommaStringSlice,
				Description: "",
				Deprecated:  true,
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
	devices, err := req.Storage.List(ctx, "devices/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(devices), nil
}

func (b *backend) pathDeviceDelete(
	ctx context.Context,
	req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, "devices/"+strings.ToLower(d.Get("name").(string)))
	if err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) pathDeviceRead(
	ctx context.Context,
	req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := strings.ToLower(d.Get("name").(string))
	device, err := b.device(ctx, req.Storage, name)
	b.Logger().Debug("pathDeviceRead", "name", name)
	if err != nil {
		return nil, err
	}
	if device == nil {
		return nil, nil
	}

	data := map[string]interface{}{}
	device.PopulateTokenData(data)
	data["registration_data"] = device.RegistrationData
	data["client_data"] = device.ClientData
	data["challenge"] = device.Challenge
	data["version"] = device.Version
	data["token_policies"] = strings.Join(device.TokenPolicies, ",")
	return &logical.Response{
		Data: data,
	}, nil
}

func (b *backend) deviceCreateUpdate(
	ctx context.Context,
	req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := strings.ToLower(d.Get("name").(string))
	b.Logger().Debug("deviceCreateUpdate", "name", name)
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

	if _, ok := d.GetOk("registration_data"); ok {
		dErr, intErr := b.updateRegistrationData(req, d, dEntry)
		if intErr != nil {
			return nil, err
		}
		if dErr != nil {
			return logical.ErrorResponse(dErr.Error()), logical.ErrInvalidRequest
		}
	}

	if _, ok := d.GetOk("client_data"); ok {
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
	b.Logger().Debug("deviceCreateUpdate", "dentry", dEntry)
	return nil, b.setDevice(ctx, req.Storage, name, dEntry)
}

func (b *backend) pathDeviceWrite(
	ctx context.Context,
	req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	registrationData := d.Get("registration_data").(string)
	if req.Operation == logical.CreateOperation && registrationData == "" {
		return logical.ErrorResponse("missing registration_data"), logical.ErrInvalidRequest
	}
	return b.deviceCreateUpdate(ctx, req, d)
}

type U2fEntry struct {
	tokenutil.TokenParams
	//Userfriendly name of the device
	Name string `json:"name" mapstructure:"name" structs:"name"`

	RegistrationData string `json:"registration_data" mapstructure:"registration_data" structs:"registration_data"`

	ClientData string `json:"client_data" mapstructure:"client_data" structs:"client_data"`

	Challenge string `json:"challenge" mapstructure:"challenge" structs:"challenge"`

	Version string `json:"version" mapstructure:"version" structs:"version"`
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

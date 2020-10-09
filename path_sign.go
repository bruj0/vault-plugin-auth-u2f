package u2fauth

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/ryankurte/go-u2f"
)

func pathSignResponse(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "signResponse/" + framework.GenericNameRegex("name"),
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback:    b.SignResponse,
				Summary:     "Authenticates a u2f device challenge",
				Description: "Authenticates a u2f device challenge",
			},
		},

		Fields: map[string]*framework.FieldSchema{
			"name": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Device name.",
			},
			"keyHandle": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "keyHandle of the device.",
			},
			"clientData": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "clientData of the device.",
			},
			"signatureData": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "signatureData of the device.",
			},
		},
		//HelpSynopsis:    pathLoginSyn,
		//HelpDescription: pathLoginDesc,
	}
}
func pathSignRequest(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "signRequest/" + framework.GenericNameRegex("name"),
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback:    b.SignRequest,
				Summary:     "Returns a challenge to authenticate a u2f device",
				Description: "Returns a challenge to authenticate a u2f device",
			},
		},
		Fields: map[string]*framework.FieldSchema{
			"name": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Device name.",
			},
		},
		//HelpSynopsis:    pathLoginSyn,
		//HelpDescription: pathLoginDesc,
	}
}

func (b *backend) SignResponse(
	ctx context.Context,
	req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	name := strings.ToLower(d.Get("name").(string))
	if name == "" {
		return nil, fmt.Errorf("missing device name")
	}
	dEntry, err := b.device(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}

	if dEntry == nil {
		b.Logger().Error("SignResponse", "Device not registered:", name)
		return logical.ErrorResponse("Device not registered"), nil
	}
	if dEntry.Challenge == nil {
		b.Logger().Error("SignResponse", "challenge not found for device:", name)
		return logical.ErrorResponse("Device not registered"), nil
	}

	keyHandle := d.Get("keyHandle").(string)
	clientData := d.Get("clientData").(string)
	signatureData := d.Get("signatureData").(string)

	resp := u2f.SignResponse{
		KeyHandle:     keyHandle,
		SignatureData: signatureData,
		ClientData:    clientData,
	}

	b.Logger().Debug("SignResponse", "regResp", resp)

	// Perform authentication
	reg, err := dEntry.Challenge.Authenticate(resp)
	if err != nil {
		// Authentication failed.
		b.Logger().Error("SignResponse", "Authentication failed", err)
		return logical.ErrorResponse("Authentication failed: " + err.Error()), nil
	}
	// TODO: expire registrations or implement a FIFO
	dEntry.Registration = append(dEntry.Registration, *reg)

	err = b.setDevice(ctx, req.Storage, name, dEntry)
	if err != nil {
		return nil, err
	}

	auth := &logical.Auth{
		Metadata: map[string]string{
			"device_name": name,
		},
		DisplayName: "u2f_" + name,
		Alias: &logical.Alias{
			Name: "u2f_" + name,
		},
	}

	roleEntry, err := b.role(ctx, req.Storage, dEntry.RoleName)
	if err != nil {
		return nil, err
	}

	roleEntry.PopulateTokenAuth(auth)
	return &logical.Response{
		Auth: auth,
	}, nil
}

func (b *backend) SignRequest(
	ctx context.Context,
	req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	var registration []u2f.Registration
	name := strings.ToLower(d.Get("name").(string))

	if name == "" {
		return nil, fmt.Errorf("missing device name")
	}

	dEntry, err := b.device(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}

	if dEntry == nil || dEntry.Registration == nil {
		return nil, fmt.Errorf("Wrong device name or device not registered")
	}

	registration = dEntry.Registration

	b.Logger().Debug("SignRequest", "registration", registration)
	c, err := u2f.NewChallenge(appID, trustedFacets, registration)
	if err != nil {
		b.Logger().Debug("SignRequest", "error", err)
		return nil, err
	}

	dEntry.Challenge = c

	err = b.setDevice(ctx, req.Storage, name, dEntry)
	if err != nil {
		return nil, err
	}

	u2fReq := c.SignRequest()
	b.Logger().Debug("SignRequest", "challenge", c)
	b.Logger().Debug("SignRequest", "u2fReq", u2fReq)
	mJSON, err := json.Marshal(u2fReq)
	if err != nil {
		return nil, err
	}
	//b.Logger().Debug("RegistrationRequest", "mJSON", string(mJSON))

	return &logical.Response{
		Data: map[string]interface{}{
			logical.HTTPContentType: "application/json",
			logical.HTTPRawBody:     string(mJSON),
			logical.HTTPStatusCode:  200,
		},
	}, nil
}

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

func pathRegistrationRequest(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "registerRequest/" + framework.GenericNameRegex("name"),
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback:    b.RegistrationRequest,
				Summary:     "Returns data to register a u2f device",
				Description: "Returns data to register a u2f device",
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

func pathRegistrationResponse(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "registerResponse/" + framework.GenericNameRegex("name"),
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback:    b.RegistrationResponse,
				Summary:     "Registers a u2f device",
				Description: "Registers a u2f device",
			},
		},

		Fields: map[string]*framework.FieldSchema{
			"name": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Device name.",
			},
			"registrationData": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "registration data of the device.",
			},
			"appId": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "registration data of the device.",
			},
			"clientData": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "registration data of the device.",
			},
			"version": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "registration data of the device.",
			},
		},
		//HelpSynopsis:    pathLoginSyn,
		//HelpDescription: pathLoginDesc,
	}
}

func (b *backend) RegistrationRequest(
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

	if dEntry == nil {
		b.Logger().Error("RegistrationResponse", "Creating new registration for device", name)
		dEntry = &DeviceData{}
		dEntry.Challenge = &u2f.Challenge{}
		dEntry.Name = name
	} else {
		b.Logger().Error("RegistrationResponse", "Updating registration for device", name)
		registration = dEntry.Registration
	}

	b.Logger().Debug("RegistrationRequest", "registration", registration)
	c, err := u2f.NewChallenge(appID, trustedFacets, registration)
	if err != nil {
		b.Logger().Debug("RegistrationRequest", "error", err)
		return nil, err
	}

	dEntry.Challenge = c

	err = b.setDevice(ctx, req.Storage, name, dEntry)
	if err != nil {
		return nil, err
	}

	u2fReq := c.RegisterRequest()
	b.Logger().Debug("RegistrationRequest", "challenge", c)
	b.Logger().Debug("RegistrationRequest", "u2fReq", u2fReq)
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

func (b *backend) RegistrationResponse(
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
		b.Logger().Error("RegistrationResponse", "Device not registered:", name)
		return nil, fmt.Errorf("Device not registered")
	}
	if dEntry.Challenge == nil {
		b.Logger().Error("RegistrationResponse", "challenge not found for device:", name)
		return nil, fmt.Errorf("Device not registered")
	}

	dEntry.RegistrationData = d.Get("registrationData").(string)
	dEntry.AppID = d.Get("appId").(string)
	dEntry.ClientData = d.Get("clientData").(string)
	dEntry.Version = d.Get("version").(string)

	b.Logger().Debug("RegistrationResponse", "dEntry", dEntry)

	regResp := u2f.RegisterResponse{
		RegistrationData: dEntry.RegistrationData,
		ClientData:       dEntry.ClientData,
	}
	b.Logger().Debug("RegistrationResponse", "regResp", regResp)
	reg, err := dEntry.Challenge.Register(regResp, &u2f.RegistrationConfig{SkipAttestationVerify: true})
	if err != nil {
		b.Logger().Error("RegistrationResponse u2f.Register", "error", err)
		return nil, fmt.Errorf("error verifying response")
	}

	dEntry.Registration = append(dEntry.Registration, *reg)

	err = b.setDevice(ctx, req.Storage, name, dEntry)
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			logical.HTTPContentType: "application/json",
			logical.HTTPRawBody:     "{\"ok\"}",
			logical.HTTPStatusCode:  200,
		},
	}, nil
}

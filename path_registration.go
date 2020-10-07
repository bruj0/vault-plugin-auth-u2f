package u2fauth

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/ryankurte/go-u2f"
)

func pathRegistrationRequest(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "registerRequest",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback:    b.RegistrationRequest,
				Summary:     "Returns data to register a u2f device",
				Description: "Returns data to register a u2f device",
			},
		},
		//HelpSynopsis:    pathLoginSyn,
		//HelpDescription: pathLoginDesc,
	}
}

func pathRegistrationResponse(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "registerResponse",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback:    b.RegistrationResponse,
				Summary:     "Registers a u2f device",
				Description: "Registers a u2f device",
			},
		},

		Fields: map[string]*framework.FieldSchema{
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
			"challenge": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "registration data of the device.",
			},
		},
		//HelpSynopsis:    pathLoginSyn,
		//HelpDescription: pathLoginDesc,
	}
}

const appID = "https://lxc1:3483"

var trustedFacets = []string{appID}

// Normally these state variables would be stored in a database.
// For the purposes of the demo, we just store them in memory.
var challenge *u2f.Challenge

var registrations []u2f.Registration

func (b *backend) RegistrationRequest(
	ctx context.Context,
	req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	b.Logger().Debug("RegistrationRequest", "registrations", registrations)
	c, err := u2f.NewChallenge(appID, trustedFacets, registrations)
	if err != nil {
		b.Logger().Debug("RegistrationRequest", "error", err)
		return nil, err
	}
	challenge = c
	u2fReq := c.RegisterRequest()
	b.Logger().Debug("RegistrationRequest", "registrations", registrations)
	b.Logger().Debug("RegistrationRequest", "challenge", challenge)
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

//TODO add an identifier for the token to register
//save it to devices
//add authentication
func (b *backend) RegistrationResponse(
	ctx context.Context,
	req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	registrationData := d.Get("registrationData").(string)
	//appID := d.Get("appId").(string)
	clientData := d.Get("clientData").(string)
	//version := d.Get("version").(string)
	//challengeStr := d.Get("challenge").(string)

	b.Logger().Debug("RegistrationResponse", "1registrations", registrations)

	if challenge == nil {
		b.Logger().Error("RegistrationResponse", "challenge not found")
		return nil, fmt.Errorf("challenge not found")
	}

	regResp := u2f.RegisterResponse{
		RegistrationData: registrationData,
		ClientData:       clientData,
	}
	reg, err := challenge.Register(regResp, &u2f.RegistrationConfig{SkipAttestationVerify: true})
	if err != nil {
		b.Logger().Error("u2f.Register", "error:", err)
		return nil, fmt.Errorf("error verifying response")
	}

	registrations = append(registrations, *reg)

	b.Logger().Debug("RegistrationResponse", "2registrations", registrations)

	return &logical.Response{
		Data: map[string]interface{}{
			logical.HTTPContentType: "application/json",
			logical.HTTPRawBody:     "{\"ok\"}",
			logical.HTTPStatusCode:  200,
		},
	}, nil
}

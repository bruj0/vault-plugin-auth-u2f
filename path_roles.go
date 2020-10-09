package u2fauth

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/go-sockaddr"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/tokenutil"
	"github.com/hashicorp/vault/sdk/logical"
)

type RoleEntry struct {
	tokenutil.TokenParams

	Policies []string

	// Duration after which the user will be revoked unless renewed
	TTL time.Duration

	// Maximum duration for which user can be valid
	MaxTTL time.Duration

	BoundCIDRs []*sockaddr.SockAddrMarshaler
}

func pathRolesList(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "roles/?",

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ListOperation: b.pathRoleList,
		},

		HelpSynopsis:    pathRoleHelpSyn,
		HelpDescription: pathRoleHelpDesc,
	}
}

func pathRoles(b *backend) *framework.Path {
	p := &framework.Path{
		Pattern: "roles/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Name of the role.",
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
			logical.DeleteOperation: b.pathRoleDelete,
			logical.ReadOperation:   b.pathRoleRead,
			logical.UpdateOperation: b.pathRoleWrite,
			logical.CreateOperation: b.pathRoleWrite,
		},

		ExistenceCheck: b.RoleExistenceCheck,

		HelpSynopsis:    pathRoleHelpSyn,
		HelpDescription: pathRoleHelpDesc,
	}
	tokenutil.AddTokenFields(p.Fields)
	return p
}
func (b *backend) role(ctx context.Context, s logical.Storage, name string) (*RoleEntry, error) {
	if name == "" {
		return nil, fmt.Errorf("missing name")
	}

	entry, err := s.Get(ctx, "roles/"+strings.ToLower(name))
	//b.Logger().Debug("device", "entry", entry)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var result RoleEntry
	if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}
	//b.Logger().Debug("device", "result", result)

	return &result, nil
}
func (b *backend) setRole(ctx context.Context, s logical.Storage, name string, dEntry *RoleEntry) error {
	entry, err := logical.StorageEntryJSON("roles/"+name, dEntry)
	if err != nil {
		return err
	}

	return s.Put(ctx, entry)
}

func (b *backend) RoleExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	entry, err := b.role(ctx, req.Storage, data.Get("name").(string))
	if err != nil {
		return false, err
	}

	return entry != nil, nil
}

func (b *backend) pathRoleList(
	ctx context.Context,
	req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	devices, err := req.Storage.List(ctx, "roles/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(devices), nil
}

func (b *backend) pathRoleDelete(
	ctx context.Context,
	req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, "roles/"+strings.ToLower(d.Get("name").(string)))
	if err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) pathRoleRead(
	ctx context.Context,
	req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := strings.ToLower(d.Get("name").(string))
	device, err := b.role(ctx, req.Storage, name)
	b.Logger().Debug("pathRoleRead", "name", name)
	if err != nil {
		return nil, err
	}
	if device == nil {
		return nil, nil
	}

	data := map[string]interface{}{}
	data["role"] = device
	return &logical.Response{
		Data: data,
	}, nil
}

func (b *backend) roleCreateUpdate(
	ctx context.Context,
	req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := strings.ToLower(d.Get("name").(string))
	b.Logger().Debug("roleCreateUpdate", "name", name)
	dEntry, err := b.role(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	// Due to existence check, user will only be nil if it's a create operation
	if dEntry == nil {
		dEntry = &RoleEntry{}
	}

	if err := dEntry.ParseTokenFields(req, d); err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}

	//b.Logger().Debug("deviceCreateUpdate", "dentry", dEntry)
	return nil, b.setRole(ctx, req.Storage, name, dEntry)
}

func (b *backend) pathRoleWrite(
	ctx context.Context,
	req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	tokenPolicies := d.Get("token_policies").(string)
	if req.Operation == logical.CreateOperation && tokenPolicies == "" {
		return logical.ErrorResponse("missing token_policies"), logical.ErrInvalidRequest
	}
	return b.roleCreateUpdate(ctx, req, d)
}

const pathRoleHelpSyn = `
Manage u2f devices roles
`

const pathRoleHelpDesc = `
This endpoint allows you to create, read, update, and delete roles for u2f devices
that are allowed to authenticate.

Deleting a role will not revoke auth for prior authenticated devices.
To do this, do a revoke on their tokens.
`

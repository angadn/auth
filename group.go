package auth

import (
	"github.com/angadn/tabular"
)

// RoleName is a string-based key to ensure our Roles are named uniquely through our
// codebase.
type RoleName string

// Role represents a realm of allowed actions that it allows upon a Resource. These
// actions themselves are 'mapped' to the Role in our business-logic, and aren't
// persisted. This allows us to iterate on our set of Roles without any 'migrations' upon
// our persisted data.
type Role struct {
	Name     RoleName
	Resource Resource
}

// NewRole is a convenience-constructor for Role.
func NewRole(name RoleName, resource Resource) (role Role) {
	role.Name = name
	role.Resource = resource
	return
}

// Roles is a type-alias for []Role.
type Roles []Role

// IDs gives us all ResourceIDs in our Roles as []string. It is handy for looking up
// lists of our entities that the User has some kind of access to.
func (roles Roles) IDs() (ids []string) {
	for _, role := range roles {
		ids = append(ids, string(role.Resource.Identifier()))
	}

	return
}

// RolesFor is a convenience-constructor for constructing an array of Roles with the same
// name but for different Resources. This is handy when a Role 'propagates'
// hierarchically through a set of Resources. For example, if an "Editor" Role for an
// Account implies an "Editor" Role for all it's constituent entities, we can use
// auth.Roles to check if the User has the "Editor" Role for the Account, or the child
// entity being accessed. The `auth` package doesn't assume any such hierarchical
// relationships and may be considered more as a handy labelling tool rather than housing
// for actual authorization business-logic. It merely appends to a set of Groups and
// allows us to check on the presence of a User in an array of Roles.
func RolesFor(name RoleName, resources ...Resource) (roles Roles) {
	for _, res := range resources {
		roles = append(roles, Role{
			Name:     name,
			Resource: res,
		})
	}

	return
}

// Group of Users with a common Role. Groups are how we interface with our persistence
// API to assign Roles to Users or list all Users with a given Role. In a Google Cloud
// Platform-like implementation, we would show the multiple groups for a given Resource
// and allow our end-user to configure them. In a BitBucket-like implementation, we'd
// mix up all the Groups for a given Resource while displaying them, with the relevant
// Role selected next to a Given user. This would allow us to change the Role assigned
// to a given User with a single click.
type Group struct {
	Role  Role
	Users []string
}

// table is a tabular representation of Groups, and helps us persist them in an SQL
// database.
var table = tabular.New(
	"groups",

	"resource_kind",
	"resource_id",
	"role_name",
	"user_id",
	"created_at",
	"updated_at",
)

package auth

import (
	"fmt"
)

// Query returns a fragment that can be used to authenticate resource access.
type Query struct {
	UserEmail string
	Kind      ResourceKind
	RoleName  RoleName
}

// NewQuery is a constructor for Query.
func NewQuery(
	userEmail string, kind ResourceKind, roleName RoleName,
) (query Query) {
	query = Query{
		UserEmail: userEmail,
		Kind:      kind,
		RoleName:  roleName,
	}

	return
}

// AsSQL return an SQL fragment that can be used to authenticate resources.
func (query Query) AsSQL() (sql string, params []interface{}, err error) {
	if query.UserEmail == "" {
		err = fmt.Errorf("invalid user email")
		return
	}

	if query.Kind == "" {
		err = fmt.Errorf("invalid resource kind")
		return
	}

	if query.RoleName == "" {
		err = fmt.Errorf("invalid role name")
		return
	}

	sql = "(`groups`.`user_id` = ? AND `groups`.`resource_kind` = ? AND `groups`.`role_name` = ?)"
	params = []interface{}{
		query.UserEmail,
		query.Kind,
		query.RoleName,
	}

	return
}

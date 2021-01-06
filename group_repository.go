package auth

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/angadn/tabular"
)

// Groups exposes our internal GroupRepository as a public API for our business layer.
var Groups GroupRepository

// WithGroupRepository configures the GroupRepository implementation that `auth` will refer.
func WithGroupRepository(r GroupRepository) {
	Groups.GroupRepositoryImpl = r
}

// GroupRepositoryImpl defines an interface with which we can persist our Groups.
type GroupRepositoryImpl interface {
	Add(ctx context.Context, user User, role Role) (err error)
	Delete(ctx context.Context, user User, role Role) (err error)
	Find(ctx context.Context, role Role) (group Group, err error)
	Free(ctx context.Context, resource Resource) (err error)
	IsUserInAny(ctx context.Context, user User, roles Roles) (ok bool, err error)
	Resources(ctx context.Context, kind ResourceKind, user User) (
		roles Roles, err error,
	)
}

// GroupRepository persists our Groups using an underlying GroupRepositoryImpl.
type GroupRepository struct {
	GroupRepositoryImpl
}

// IsInAny is a convenience-method that calls `IsUserInAny` with the User in the current
// Context.
func (repo GroupRepository) IsInAny(ctx context.Context, roles Roles) (
	ok bool, err error,
) {
	var user User
	if user, err = FromContext(ctx); err != nil {
		return
	}

	ok, err = repo.IsUserInAny(ctx, user, roles)
	return
}

// GroupMySQLRepository implements GroupRepository in MySQL.
type GroupMySQLRepository struct {
	db *sql.DB
}

// NewGroupMySQLRepositoryImpl is a constructor for GroupMySQLRepository.
func NewGroupMySQLRepositoryImpl(db *sql.DB) (repo GroupRepository, err error) {
	mysqlRepo := new(GroupMySQLRepository)
	mysqlRepo.db = db
	repo.GroupRepositoryImpl = mysqlRepo
	err = mysqlRepo.db.Ping()
	return
}

// Add a User to a Group for the given Role, creating a Group if it doesn't exist. Add
// is an idempotent action and does nothing silently if the User already has the given
// Role.
func (repo *GroupMySQLRepository) Add(
	ctx context.Context, user User, role Role,
) (err error) {
	var (
		kind = role.Resource.Kind()
		id   = role.Resource.Identifier()
	)

	_, err = repo.db.ExecContext(ctx, table.Insertion(
		"%s ON DUPLICATE KEY UPDATE `user_id` = VALUES(`user_id`)",
		"created_at", "NOW()",
		"updated_at", "NOW()",
	),
		string(kind),
		string(id),
		string(role.Name),
		user.GetID(),
	)

	return
}

// Delete a Role for a User.
func (repo *GroupMySQLRepository) Delete(
	ctx context.Context, user User, role Role,
) (err error) {
	var (
		kind = role.Resource.Kind()
		id   = role.Resource.Identifier()
	)

	_, err = repo.db.ExecContext(
		ctx,
		"DELETE FROM `groups` WHERE `resource_kind` = ? AND `resource_id` = ? AND `role_name` = ? AND `user_id` = ?",
		string(kind),
		string(id),
		string(role.Name),
		user.GetID(),
	)

	return
}

// Free deletes all Groups attached to the given Resource. It is intended to be called at
// the end of the Resource's lifecycle.
func (repo *GroupMySQLRepository) Free(ctx context.Context, resource Resource) (
	err error,
) {
	var (
		kind = resource.Kind()
		id   = resource.Identifier()
	)

	_, err = repo.db.ExecContext(
		ctx,
		"DELETE FROM `groups` WHERE `resource_kind` = ? AND `resource_id` = ?",
		string(kind),
		string(id),
	)

	return
}

// Find a Group of Users that are assigned a given Role. This allows us to visually list
// them and allow for the end-user to reconfigure our Groups.
func (repo *GroupMySQLRepository) Find(ctx context.Context, role Role) (
	group Group, err error,
) {
	var (
		kind = role.Resource.Kind()
		id   = role.Resource.Identifier()
	)

	var rows *sql.Rows
	if rows, err = repo.db.QueryContext(ctx, table.Selection(
		"SELECT %s FROM `groups` WHERE `groups`.`resource_kind` = ? AND `groups`.`resource_id` = ? AND `groups`.`role_name` = ?",
	),
		string(kind),
		string(id),
		string(role.Name),
	); err != nil {
		return
	}

	defer rows.Close()

	for rows.Next() {
		var (
			res    resourceImpl
			userID string
		)

		if err = tabular.NewScanner(
			&res.kind,
			&res.id,
			&group.Role.Name,
			&userID,
			&tabular.Scapegoat{},
			&tabular.Scapegoat{},
		).Scan(rows); err != nil {
			return
		}

		group.Users = append(group.Users, userID)
	}

	return
}

// IsUserInAny checks whether the given User has one or more of the given Roles. It's results
// can only be reliably consumed when `err` is `nil`.
func (repo *GroupMySQLRepository) IsUserInAny(ctx context.Context, user User, roles Roles) (
	ok bool, err error,
) {
	if user.GetID() == master.GetID() && user.GetSecret() == master.GetSecret() {
		ok = true
		return
	}

	var args []interface{}
	for _, r := range roles {
		var (
			kind = r.Resource.Kind()
			id   = r.Resource.Identifier()
		)

		args = append(
			args,
			string(kind),
			string(id),
			string(r.Name),
			user.GetID(),
		)
	}

	if len(roles) == 0 {
		return
	}

	err = repo.db.QueryRowContext(ctx, fmt.Sprintf(
		"SELECT IF(COUNT(*), \"true\", \"false\") FROM `groups` WHERE %s",
		strings.TrimRight(strings.Repeat(
			"(`groups`.`resource_kind` = ? AND `groups`.`resource_id` = ? AND `groups`.`role_name` = ? AND `groups`.`user_id` = ?) OR", len(roles),
		), " OR"),
	), args...).Scan(&ok)

	return
}

// Resources lists all of the Resources of a given ResourceKind that a User has access to
// via any Role assigned to her.
func (repo *GroupMySQLRepository) Resources(
	ctx context.Context, kind ResourceKind, user User,
) (roles Roles, err error) {
	var rows *sql.Rows
	if rows, err = repo.db.QueryContext(ctx, table.Selection(
		"SELECT %s FROM `groups` WHERE `groups`.`resource_kind` = ? AND `groups`.`user_id` = ?",
	),
		string(kind),
		user.GetID(),
	); err != nil {
		return
	}

	defer rows.Close()

	for rows.Next() {
		var (
			role Role
			res  resourceImpl
		)

		if err = tabular.NewScanner(
			&res.kind,
			&res.id,
			&role.Name,
			&tabular.Scapegoat{},
			&tabular.Scapegoat{},
			&tabular.Scapegoat{},
		).Scan(rows); err != nil {
			return
		}

		role.Resource = res
		roles = append(roles, role)
	}

	return
}

# auth
A package to provide user-authentication as well as authorization (at some point in time).

## Authentication

```
var (
    err  error
    user User
)

defer session.Cancel() // Will write internal `err` as Response, in case of error.

if user, err := session.Auth(); err != nil {
    log.Printf(err.Error())
    return
}

...
```

## Authorization
A simple, familiar system inspired by the likes of Google Cloud Platform, BitBucket, and Atlassian Confluence.

### Philosophy
`auth` aims to simply provide a way to persist various roles a user may be assigned for resources. It doesn't implicitly infer any hierarchy among these roles *or* resources. For example, whether users with the role of *Owner*s are allowed to do everything those with the role of *Editor*s can, is left up to your business-logic. The idea is to keep our persistence of authorization as light as possible, so as to avoid the any complex migrations to them in case the rules change on us.

Resources are themselves more often than not hierarchical in nature - *i.e.* an `Account` can contain multiple `Campaign`s, and therefore an *Editor* of `Account` is also an *Editor* of it's underlying `Campaign`s. However, we steer clear of any such rule-definitions in our framework. This allows the developer to build both, implicitly whitelisting, as well as explicitly blacklisting systems as she may deem fit for her use-case.

This impedes us from providing certain auto-magic out-of-the-box, like disallowing a end-user from deleting herself from an *Owner*s group. Rather, it transfers this responsibility to the developer, who may choose to allow it (creating a sophisticated system for ownership transfers), or disallow it.

Lastly, we make a rather bold deviation from most authorization-frameworks by not even persisting what actions a Role may allow a User to perform upon a Resource - such as *C*reate, *R*ead, *U*pdate, *D*elete or a combination of the aforementioned. This is largely because it is often unnatural for actions to be labeled so. Take for instance an email-sending system - we can easily see how an e*X*ecute label would be required for creating a sophisticated system. For other Resources within the same system, this label would make little sense. As fewer things are scarcer that discipline among software-developers, we steer clear of a situation where system-wide changes would require us to relabel all the persisted actions, by not persisting actions to begin with. In sophisticated systems, forcing *CRUD* labels onto Roles create more problems than they would solve.

### Ubiquitous Language
* A **Resource** represents an Entity in the business-layer.
* A **Role** represents a logical set of *allow*ed actions on a **Resource**.
* A **Group** is a set of **Users** for a **Role**.
* A **User** is *allow*ed to perform an action if present in one or more **Group**s for the corresponding **Role**(s).

### Usage
Inside `Campaign`:

```
func (campaign Campaign) Resource() (kind auth.ResourceKind, id auth.ResourceID) {
    return ResourceKind, auth.ResourceID(campaign.ID)
}

func (campaign Campaign) NewOwnerRole() (ownerRole auth.Role) {
    return NewRole(OwnerRole, campaign.Resource())
}

func (campaign Campaign) OwnerRoles() (ownerRoles auth.Roles) {
    ownerRoles = append(
        ownerRoles,
        campaign.NewOwnerRole(),
        campaign.User.OwnerRoles()..., // Refers to the parent account
    )

    return
}
```

Now, while creating a new Campaign:

```
// Add the creator of a Campaign to it's 'Owner' group.
auth.Groups.Add(ctx, user, campaign.NewOwnerRole())
```

Sometime later, in our Services...

```
// Check
if ok, err = auth.Groups.Belongs(ctx, user, campaign.OwnerRoles()); err != nil {
    return
} else if !ok {
    err = fmt.Errorf("only owner(s) can perform this action")
    return
}

...
```
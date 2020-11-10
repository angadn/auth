package auth

// Owner is the role that has access to all resources
var Owner = Role{
	Name:     RoleName("owner"),
	Resource: PlatformResource,
}

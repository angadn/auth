package auth

import (
	"go.uber.org/fx"
)

// Module is an fx.Options that includes provider (constructors)
// and invoke (register) functions of the package
var Module = fx.Options(
	fx.Provide(
		NewGroupMySQLRepository,
	),
	fx.Invoke(
		WithRepository,
		WithGroupRepository,
	),
)

// AWSCognitoModule is an fx.Options that sets up our AWS Cognito RBAC.
var AWSCognitoModule = fx.Options(
	fx.Provide(
		NewAWSCognitoRBAC,
	),
	fx.Invoke(
		WithRBAC,
	),
)

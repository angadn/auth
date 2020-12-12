package auth

import (
	"context"

	"github.com/angadn/config"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
)

// RBAC is an interface that any RBAC provider must implement.
type RBAC interface {
	Authenticate(
		ctx context.Context, username, password string,
	) (user User, ok bool, err error)
}

// AWSCognitoRBAC implements the RBAC interface for AWS Cognito.
type AWSCognitoRBAC struct {
	ses *session.Session
}

// NewAWSCognitoRBAC is the provider for an AWS Cognito-backed Repository.
func NewAWSCognitoRBAC(
	ctx context.Context, cfg config.Source,
) (rbac RBAC, err error) {
	ret := new(AWSCognitoRBAC)

	var region config.Value
	if region, err = cfg.Get(ctx, config.Key("AWS_REGION")); err != nil {
		return
	}

	ret.ses = session.New(&aws.Config{
		Region: aws.String(string(region)),
	})

	rbac = ret
	return
}

// Authenticate implements Repository#Authenticate for AWS Cognito.
func (repo *AWSCognitoRBAC) Authenticate(
	ctx context.Context, username, password string,
) (user User, ok bool, err error) {
	var cip = cognitoidentityprovider.New(repo.ses)
	if _, err = cip.InitiateAuth(&cognitoidentityprovider.InitiateAuthInput{
		AuthFlow: aws.String("USER_PASSWORD_AUTH"),
		AuthParameters: map[string]*string{
			"USERNAME": aws.String(username),
			"PASSWORD": aws.String(password),
		},
	}); err != nil {
		return
	}

	ok = true
	user = &awsUser{
		id:         username,
		secret:     password,
		isVerified: true,
	}

	return
}

type awsUser struct {
	id, secret string
	isVerified bool
}

func (user *awsUser) GetID() (id string) {
	id = user.id
	return
}

func (user *awsUser) GetSecret() (secret string) {
	secret = user.secret
	return
}

func (user *awsUser) GetIsVerified() (ok bool) {
	ok = user.isVerified
	return
}

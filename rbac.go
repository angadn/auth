package auth

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
)

// RBAC is an interface that any RBAC provider must implement.
type RBAC interface {
	Authenticate(
		ctx context.Context, username, password string,
	) (user User, ok bool, err error)
}

// AWSCognitoRBAC implements the RBAC interface for AWS Cognito.
type AWSCognitoRBAC struct {
	cfg aws.Config
}

// NewAWSCognitoRBAC is the provider for an AWS Cognito-backed Repository.
func NewAWSCognitoRBAC(
	cfg aws.Config,
) (rbac RBAC, err error) {
	ret := new(AWSCognitoRBAC)
	ret.cfg = cfg
	rbac = ret
	return
}

// Authenticate implements Repository#Authenticate for AWS Cognito.
func (repo *AWSCognitoRBAC) Authenticate(
	ctx context.Context, username, accessToken string,
) (user User, ok bool, err error) {
	var out *cognitoidentityprovider.GetUserOutput
	if out, err = cognitoidentityprovider.NewFromConfig(repo.cfg).GetUser(
		context.TODO(),
		&cognitoidentityprovider.GetUserInput{
			AccessToken: aws.String(accessToken),
		},
	); err != nil {
		return
	} else if out == nil {
		err = ErrInvalidUserCredentials
		return
	}

	for _, kp := range out.UserAttributes {
		if *kp.Name == "email" && *kp.Value == username {
			ok = true
			break
		}
	}

	if !ok {
		err = ErrInvalidUserCredentials
		return
	}

	user = &awsUser{
		id:         username,
		secret:     accessToken,
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

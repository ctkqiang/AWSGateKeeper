package model

import "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"

type Audit struct {
	CognitoClient *cognitoidentityprovider.Client
}

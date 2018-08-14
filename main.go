package main

import (
	"context"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
)

func HandleAuth(ctx context.Context, req events.APIGatewayCustomAuthorizerRequest) (events.APIGatewayCustomAuthorizerResponse, error) {
	// token := strings.ToLower(evt.AuthorizationToken)
	// validate the incoming token
	// and produce the principal user identifier associated with the token

	// this could be accomplished in a number of ways:
	// 1. Call out to OAuth provider
	// 2. Decode a JWT token in-line
	// 3. Lookup in a self-managed DB
	principalID := "user|xxxx"

	// if the client token is not recognized or invalid
	// you can send a 401 Unauthorized response to the client by failing like so:
	// return nil, errors.New("Unauthorized")

	// if the token is valid, a policy should be generated which will allow or deny access to the client

	// if access is denied, the client will receive a 403 Access Denied response
	// if access is allowed, API Gateway will proceed with the back-end integration configured on the method that was called

	methodArn := req.MethodArn
	arnPartials := strings.Split(methodArn, ":")
	region := arnPartials[3]
	awsAccountId := arnPartials[4]
	apiGatewayArnPartials := strings.Split(arnPartials[5], "/")
	restApiId := apiGatewayArnPartials[0]
	stage := apiGatewayArnPartials[1]
	//httpMethod := apiGatewayArnPartials[2]
	//resource := "" // root resource
	// if len(apiGatewayArnPartials) == 4 {
	// 	resource = apiGatewayArnPartials[3]
	//}

	// this function must generate a policy that is associated with the recognized principal user identifier.
	// depending on your use case, you might store policies in a DB, or generate them on the fly

	// keep in mind, the policy is cached for 5 minutes by default (TTL is configurable in the authorizer)
	// and will apply to subsequent calls to any method/resource in the RestApi
	// made with the same token

	// the example policy below denies access to all resources in the RestApi

	principalDocumentBuilder := NewAPIGatewayCustomAuthorizerPolicyBuilder(region, awsAccountId, restApiId, stage)
	err := principalDocumentBuilder.DenyAllMethods()

	if err != nil {
		return events.APIGatewayCustomAuthorizerResponse{}, err
	}

	return events.APIGatewayCustomAuthorizerResponse{
		PrincipalID:    principalID,
		PolicyDocument: principalDocumentBuilder.Build(),
		Context: map[string]interface{}{
			"stringKey":  "string",
			"numberKey":  123,
			"booleanKey": true,
		},
	}, nil

}

func main() {
	lambda.Start(HandleAuth)
}

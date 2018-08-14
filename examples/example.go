package examples

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/papadoubi/golang-aws-lambda-authorizer-example/auth"
)

// CustomClaims example, change if needed
type CustomClaims struct {
	Issuer    string   `json:"iss,omitempty"`
	Audience  string   `json:"aud,omitempty"`
	Subject   string   `json:"sub,omitempty"`
	Scope     []string `json:"scope,omitempty"`
	ExpiresAt int64    `json:"exp,omitempty"`
	IssuedAt  int64    `json:"iat,omitempty"`
}

// Valid ... always. Implement jwt.Claims interface
func (c CustomClaims) Valid() error {
	return nil
}

// ExampleHandler checks JWT token, extracts principalID from custom claims and allows
// access to all resources in the API if the token is valid
func ExampleHandler(ctx context.Context, req events.APIGatewayCustomAuthorizerRequest) (events.APIGatewayCustomAuthorizerResponse, error) {
	tokenStr := strings.ToLower(req.AuthorizationToken)

	claims := &CustomClaims{}

	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		return []byte("very_secret_key"), nil
	})

	if err != nil || !token.Valid {
		return events.APIGatewayCustomAuthorizerResponse{}, errors.New("invalid token")
	}

	claims, ok := token.Claims.(*CustomClaims)

	if !ok {
		return events.APIGatewayCustomAuthorizerResponse{}, errors.New("invalid token")
	}

	principalID := claims.Issuer
	methodArn := req.MethodArn
	arnPartials := strings.Split(methodArn, ":")
	region := arnPartials[3]
	awsAccountID := arnPartials[4]
	apiGatewayArnPartials := strings.Split(arnPartials[5], "/")
	restAPIID := apiGatewayArnPartials[0]
	stage := apiGatewayArnPartials[1]

	// the example policy below allows access to all resources in the RestAPI

	principalDocumentBuilder := auth.NewAPIGatewayCustomAuthorizerPolicyBuilder(region, awsAccountID, restAPIID, stage)
	err = principalDocumentBuilder.AllowAllMethods()

	if err != nil {
		return events.APIGatewayCustomAuthorizerResponse{}, err
	}

	return events.APIGatewayCustomAuthorizerResponse{
		PrincipalID:    principalID,
		PolicyDocument: principalDocumentBuilder.Build(),
	}, nil
}

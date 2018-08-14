package auth

import (
	"errors"
	"strings"

	"github.com/aws/aws-lambda-go/events"
)

const (
	PolicyVersion = "2012-10-17" // override if necessary
	MethodGet     = "GET"
	MethodHead    = "HEAD"
	MethodPost    = "POST"
	MethodPut     = "PUT"
	MethodPatch   = "PATCH"
	MethodDelete  = "DELETE"
	MethodOptions = "OPTIONS"
	MethodAll     = "*"
	AllowEffect   = "Allow"
	DenyEffect    = "Deny"
)

type APIGatewayCustomAuthorizerPolicyBuilder struct {
	Region       string
	AWSAccountID string
	RestAPIID    string
	Stage        string
	Policy       *events.APIGatewayCustomAuthorizerPolicy
}

func NewAPIGatewayCustomAuthorizerPolicyBuilder(region, accountID, apiID, stage string) *APIGatewayCustomAuthorizerPolicyBuilder {
	return &APIGatewayCustomAuthorizerPolicyBuilder{
		Region:       region,
		AWSAccountID: accountID,
		RestAPIID:    apiID,
		Stage:        stage,
		Policy:       &events.APIGatewayCustomAuthorizerPolicy{Version: PolicyVersion},
	}
}

func (p *APIGatewayCustomAuthorizerPolicyBuilder) Build() events.APIGatewayCustomAuthorizerPolicy {
	return *p.Policy
}

func (p *APIGatewayCustomAuthorizerPolicyBuilder) addMethod(effect, method, resource string) error {
	arn := "arn:aws:execute-api:" +
		p.Region + ":" +
		p.AWSAccountID + ":" +
		p.RestAPIID + "/" +
		p.Stage + "/" +
		method + "/" +
		strings.TrimLeft(resource, "/")

	switch strings.ToLower(effect) {
	case "allow":
		effect = AllowEffect
	case "deny":
		effect = DenyEffect
	default:
		return errors.New("Invalid effect")
	}

	stmt := events.IAMPolicyStatement{
		Effect:   effect,
		Action:   []string{"execute-api:Invoke"},
		Resource: []string{arn},
	}

	p.Policy.Statement = append(p.Policy.Statement, stmt)

	return nil
}

func (r *APIGatewayCustomAuthorizerPolicyBuilder) AllowAllMethods() error {
	return r.addMethod(AllowEffect, MethodAll, "*")
}

func (r *APIGatewayCustomAuthorizerPolicyBuilder) DenyAllMethods() error {
	return r.addMethod(DenyEffect, MethodAll, "*")
}

func (r *APIGatewayCustomAuthorizerPolicyBuilder) AllowMethod(method, resource string) error {
	return r.addMethod(AllowEffect, method, resource)
}

func (r *APIGatewayCustomAuthorizerPolicyBuilder) DenyMethod(method, resource string) error {
	return r.addMethod(DenyEffect, method, resource)
}

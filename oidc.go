package jade

import (
	"context"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type oidcProvider[T Claims] struct {
	*provider[T]
	oidc *oidc.Provider
}
type OIDCOptions struct {
	Options
	AuthOptions []oauth2.AuthCodeOption
	Issuer      string
	UseNonce    bool
	UsePKCE     bool
}

type ParseIDTokenOptions struct {
	SkipAccessTokenCheck bool
	AccessToken          string
}

// newOIDCProvider creates a new provider for the given issuer and options.
//
// This function wraps the go-oidc NewProvider function and the newProvider
// function in this package. It takes an OIDCOptions struct and returns an
// oidcProvider, which is a Provider that wraps an *oidc.Provider and can
// be used to authenticate users.
//
// The returned Provider will have the given name, scopes, and auth options.
// The EndPoint field of the Provider's ProviderOptions will be set to the
// Provider's Endpoint().
func NewOIDCProvider[T Claims](opts *OIDCOptions) (*oidcProvider[T], error) {
	oidcP, err := oidc.NewProvider(context.Background(), opts.Issuer)
	if err != nil {
		return nil, err
	}
	options := &ProviderOptions{
		Options:     opts.Options,
		AuthOptions: opts.AuthOptions,
		EndPoint:    oidcP.Endpoint(),
		UsePKCE:     opts.UsePKCE,
	}
	options.Scopes = opts.Scopes
	p, err := NewProvider[T](options)
	p.useNonce = opts.UseNonce
	if err != nil {
		return nil, err
	}
	return &oidcProvider[T]{p, oidcP}, nil
}

// verifyIDToken verifies the provided ID token using the OIDC provider's verifier.
// It optionally skips the client ID check if the provided oidc.Config is nil.
// The function also verifies the access token hash if the SkipAccessTokenCheck option
// is not set and the token contains an AccessTokenHash.
// Returns the verified oidc.IDToken if successful, or an error if verification fails.

func (p *oidcProvider[T]) verifyIDToken(ctx context.Context, conf *oidc.Config, idToken string, options ParseIDTokenOptions) (*oidc.IDToken, error) {
	if conf == nil {
		conf = &oidc.Config{
			SkipClientIDCheck: true,
		}
	}
	verifier := p.oidc.VerifierContext(ctx, conf)
	token, err := verifier.Verify(ctx, idToken)
	if err != nil {
		return nil, err
	}

	if !options.SkipAccessTokenCheck && token.AccessTokenHash != "" {
		if err := token.VerifyAccessToken(options.AccessToken); err != nil {
			return nil, err
		}
	}
	return token, nil
}

// userInfo fetches user info from the OIDC provider using the given token.
// It requires the token to be valid, and returns an error if it is not.
// The function returns an error if the user info request fails.
func (p *oidcProvider[T]) userInfo(ctx context.Context, token *oauth2.Token) (u *User, err error) {

	user, err := p.oidc.UserInfo(ctx, p.TokenSource(ctx, token))
	if err != nil {
		return
	}
	var v T
	err = user.Claims(&v)
	if err != nil {
		return
	}
	return v.MarshalToUser(), nil
}

// parseIDToken extracts and verifies the ID token from the given OAuth2 token.
// It first checks if the token is valid, returning an error if it is not.
// The function extracts the "id_token" from the token's extra fields and verifies it
// using the OIDC provider's verifier. If verification is successful, it returns the
// verified oidc.IDToken. If the ID token is not present or verification fails, it
// returns an error.

func (p *oidcProvider[T]) parseIDToken(ctx context.Context, token *Token) (*oidc.IDToken, error) {
	idtokenStr, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("no id_token in token")
	}
	return p.verifyIDToken(ctx, &oidc.Config{
		ClientID: p.provider.Config.ClientID,
	}, idtokenStr, ParseIDTokenOptions{
		AccessToken: token.AccessToken,
	})

}

// parseClaims extracts user claims from the provided ID token.
// It decodes the token claims into the specified type T, which
// implements the OIDCClaims interface. If successful, it returns
// the user claims as a jade.User object. If the claim extraction
// fails, it returns an error.

func (p *oidcProvider[T]) parseClaims(token *oidc.IDToken) (*User, error) {
	var v T
	err := token.Claims(&v)
	if err != nil {
		return nil, err
	}
	return v.MarshalToUser(), nil
}

// GetUserData returns the user data associated with the given token.
// It first checks if the token is valid, returning an error if it is not.
// If the token is valid, it extracts and verifies the ID token using the
// OIDC provider's verifier. The function then extracts the user claims from
// the ID token and returns them as a jade.User object.
// If the ID token is not present, verification fails, or the claim extraction
// fails, the function returns an error.
func (p *oidcProvider[T]) GetUserData(ctx context.Context, token *Token) (*User, error) {

	if !p.provider.IsTokenValid(ctx, token) {
		return nil, fmt.Errorf("token is not valid")
	}
	u, err := p.parseClaims(token.IDToken)
	if err != nil || u.ID == "" {
		return p.userInfo(ctx, token.Token)
	}
	return u, nil
}

// GetOAuthToken exchanges the given authorization code for an access token.
// It returns a pointer to the received token, which contains the ID token
// parsed from the token's extra fields. If the exchange fails or the ID token
// is not present, the function returns an error.
func (p *oidcProvider[T]) GetOAuthToken(code string, opts ...oauth2.AuthCodeOption) (*Token, error) {
	tk, err := p.provider.GetOAuthToken(code, opts...)
	if err != nil {
		return nil, err
	}
	id, err := p.parseIDToken(context.Background(), tk)
	if err != nil {
		return nil, err
	}
	tk.IDToken = id
	return tk, nil
}

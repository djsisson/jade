package jade

import (
	"strings"

	"golang.org/x/oauth2"
)

type ProviderOptions struct {
	Options
	Name        string
	EndPoint    oauth2.Endpoint
	AuthOptions []oauth2.AuthCodeOption
	ApiURL      string
	UsePKCE     bool
	Claims      Claims
}

type Options struct {
	ClientID     string
	ClientSecret string
	CallbackURL  string
	Scopes       []string
}

// WithPrompt returns an AuthCodeOption that adds the "prompt" parameter to the
// authorize URL. The value of the parameter is the space-separated list of
// given prompts.
//
// See https://developers.google.com/identity/protocols/OpenIDConnect#promptrelatedparameters
func WithPrompt(prompt ...string) oauth2.AuthCodeOption {
	if len(prompt) == 0 {
		return nil
	}
	return oauth2.SetAuthURLParam("prompt", strings.Join(prompt, " "))
}

// WithHostedDomain returns an AuthCodeOption that adds the "hd" parameter to the
// authorize URL. The value of the parameter is the given domain.
//
// See https://developers.google.com/identity/protocols/OpenIDConnect#hd-param
func WithHostedDomain(hd string) oauth2.AuthCodeOption {
	if hd == "" {
		return nil
	}
	return oauth2.SetAuthURLParam("hd", hd)
}

// WithLoginHint returns an AuthCodeOption that adds the "login_hint"
// parameter to the authorize URL. The value of the parameter is the given
// login hint.
//
// See https://developers.google.com/identity/protocols/OpenIDConnect#login_hint
func WithLoginHint(loginHint string) oauth2.AuthCodeOption {
	if loginHint == "" {
		return nil
	}
	return oauth2.SetAuthURLParam("login_hint", loginHint)
}

// WithScopes returns an AuthCodeOption that adds the "scope" parameter to the
// authorize URL. The value of the parameter is the space-separated list of
// given scopes.
//
// See https://developers.google.com/identity/protocols/OpenIDConnect#scopes
func WithScopes(scopes ...string) oauth2.AuthCodeOption {
	if len(scopes) == 0 {
		return nil
	}
	return oauth2.SetAuthURLParam("scope", strings.Join(scopes, " "))
}

// WithForcedApprovalPrompt returns an AuthCodeOption that forces the user to
// approve the request every time, even if they previously approved a
// request with the same client_id and scope.
func WithForcedApprovalPrompt() oauth2.AuthCodeOption {
	return oauth2.ApprovalForce
}

// WithOfflineAccess returns an AuthCodeOption that requests a refresh token
// that can be used to obtain a new access token when the user is not present.
//
// See https://developers.google.com/identity/protocols/OpenIDConnect#offline
func WithOfflineAccess() oauth2.AuthCodeOption {
	return oauth2.AccessTypeOffline
}

// WithOnlineAccess returns an AuthCodeOption that requests an access token
// that can be used when the user is present.
//
// See https://developers.google.com/identity/protocols/OpenIDConnect#online

func WithOnlineAccess() oauth2.AuthCodeOption {
	return oauth2.AccessTypeOnline
}

// WithIdentityProvider returns an AuthCodeOption that adds the "identity_provider"
// parameter to the authorize URL, which can be used to specify the identity
// provider that the user should use to authenticate.
//
// See https://developers.google.com/identity/protocols/OpenIDConnect#hd-param
func WithIdentityProvider(idp string) oauth2.AuthCodeOption {
	return oauth2.SetAuthURLParam("identity_provider", idp)
}

// WithNonce returns an AuthCodeOption that adds the "nonce" parameter to the
// authorize URL. The value of the parameter is the given nonce.
//
// See https://developers.google.com/identity/protocols/OpenIDConnect#nonce
func WithNonce(nonce string) oauth2.AuthCodeOption {
	return oauth2.SetAuthURLParam("nonce", nonce)
}

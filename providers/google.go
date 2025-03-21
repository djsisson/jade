package providers

import (
	"github.com/djsisson/jade"
	"golang.org/x/oauth2"
)

var (
	GoogleIssuer = "https://accounts.google.com"
	GoogleScopes = []string{"openid", "profile", "email"}
	GoogleApiUrl = "https://www.googleapis.com/oauth2/v2/userinfo"
)

type GoogleUser struct {
	ID            string `json:"sub,omitempty"`
	Issuer        string `json:"iss,omitempty"`
	Name          string `json:"name,omitempty"`
	FirstName     string `json:"given_name,omitempty"`
	LastName      string `json:"family_name,omitempty"`
	Picture       string `json:"picture,omitempty"`
	Email         string `json:"email,omitempty"`
	VerifiedEmail bool   `json:"verified_email,omitempty"`
	EmailVerified bool   `json:"email_verified,omitempty"`
	Locale        string `json:"locale,omitempty"`
	HostedDomain  string `json:"hd,omitempty"`
}

func (u *GoogleUser) MarshalToUser() *jade.User {
	return &jade.User{
		ID:            u.ID,
		Issuer:        "google",
		Name:          u.Name,
		FirstName:     u.FirstName,
		LastName:      u.LastName,
		Picture:       u.Picture,
		Email:         u.Email,
		EmailVerified: u.EmailVerified,
		Locale:        u.Locale,
	}
}

func NewGoogleProvider(o *jade.Options, opts ...oauth2.AuthCodeOption) (jade.Provider, error) {

	if len(o.Scopes) == 0 {
		o.Scopes = GoogleScopes
	}
	if len(opts) == 0 {
		opts = []oauth2.AuthCodeOption{
			jade.WithOfflineAccess(),
			jade.WithForcedApprovalPrompt(),
		}
	}

	p, err := jade.NewOIDCProvider[*GoogleUser](&jade.OIDCOptions{
		Options:     *o,
		Name:        "google",
		AuthOptions: opts,
		Issuer:      GoogleIssuer,
		UseNonce:    true,
		UsePKCE:     true,
	})

	if err != nil {
		return nil, err
	}
	return p, nil
}

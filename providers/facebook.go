package providers

import (
	"github.com/djsisson/jade"
	"golang.org/x/oauth2"
)

var (
	FacebookIssuer = "https://limited.facebook.com"
	FacebookScopes = []string{"openid", "email", "public_profile"}
)

type FacebookUser struct {
	ID        string `json:"sub,omitempty"`
	Name      string `json:"name,omitempty"`
	Email     string `json:"email,omitempty"`
	Picture   string `json:"picture,omitempty"`
	FirstName string `json:"given_name,omitempty"`
	LastName  string `json:"family_name,omitempty"`
}

func (f *FacebookUser) MarshalToUser() *jade.User {
	return &jade.User{
		ID:        f.ID,
		Issuer:    "facebook",
		Name:      f.Name,
		FirstName: f.FirstName,
		LastName:  f.LastName,
		Picture:   f.Picture,
		Email:     f.Email,
	}
}

func NewFacebookProvider(o *jade.Options, opts ...oauth2.AuthCodeOption) (jade.Provider, error) {
	if o.Name == "" {
		o.Name = "facebook"
	}
	if len(o.Scopes) == 0 {
		o.Scopes = FacebookScopes
	}
	if len(opts) == 0 {
		opts = []oauth2.AuthCodeOption{
			jade.WithOfflineAccess(),
		}
	}

	p, err := jade.NewOIDCProvider[*FacebookUser](&jade.OIDCOptions{
		Options:     *o,
		AuthOptions: opts,
		Issuer:      FacebookIssuer,
		UseNonce:    true,
		UsePKCE:     true,
	})

	if err != nil {
		return nil, err
	}
	return p, nil
}

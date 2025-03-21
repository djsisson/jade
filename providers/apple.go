package providers

import (
	"github.com/djsisson/jade"
	"golang.org/x/oauth2"
)

var (
	AppleIssuer = "https://appleid.apple.com"
	AppleScopes = []string{"email", "name"}
)

type appleName struct {
	FirstName string `json:"firstName,omitempty"`
	LastName  string `json:"lastName,omitempty"`
}

type appleUser struct {
	Name          appleName `json:"name"`
	Email         string    `json:"email,omitempty"`
	EmailVerified bool      `json:"email_verified,omitempty"`
	ID            string    `json:"sub,omitempty"`
}

func (u *appleUser) MarshalToUser() *jade.User {
	return &jade.User{
		ID:            u.ID,
		Issuer:        "apple",
		Name:          u.Name.FirstName + " " + u.Name.LastName,
		EmailVerified: u.EmailVerified,
		Email:         u.Email,
		FirstName:     u.Name.FirstName,
		LastName:      u.Name.LastName,
	}
}

func NewAppleProvider(o *jade.Options, opts ...oauth2.AuthCodeOption) (jade.Provider, error) {

	if len(o.Scopes) == 0 {
		o.Scopes = AppleScopes
	}
	if len(opts) == 0 {
		opts = []oauth2.AuthCodeOption{
			jade.WithOfflineAccess(),
		}
	}

	p, err := jade.NewOIDCProvider[*appleUser](&jade.OIDCOptions{
		Options:     *o,
		Name:        "apple",
		AuthOptions: opts,
		Issuer:      AppleIssuer,
	})

	if err != nil {
		return nil, err
	}
	return p, nil
}

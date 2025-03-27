package providers

import (
	"github.com/djsisson/jade"
	"golang.org/x/oauth2"
)

var (
	KeycloakScopes = []string{"openid", "profile", "email"}
)

type KeycloakUser struct {
	ID        string `json:"sub,omitempty"`
	Name      string `json:"name,omitempty"`
	Email     string `json:"email,omitempty"`
	FirstName string `json:"given_name,omitempty"`
	LastName  string `json:"family_name,omitempty"`
	Username  string `json:"preferred_username,omitempty"`
	Picture   string `json:"picture,omitempty"`
}

func (k *KeycloakUser) MarshalToUser() *jade.User {
	return &jade.User{
		ID:        k.ID,
		Issuer:    "keycloak",
		Name:      k.Name,
		Email:     k.Email,
		FirstName: k.FirstName,
		LastName:  k.LastName,
		UserName:  k.Username,
		Picture:   k.Picture,
	}
}

func NewKeycloakProvider(BaseURL, Realm string, o *jade.Options, opts ...oauth2.AuthCodeOption) (jade.Provider, error) {

	if o.Name == "" {
		o.Name = "keycloak"
	}
	if len(o.Scopes) == 0 {
		o.Scopes = KeycloakScopes
	}
	if len(opts) == 0 {
		opts = []oauth2.AuthCodeOption{
			jade.WithOfflineAccess(),
		}
	}

	p, err := jade.NewOIDCProvider[*KeycloakUser](&jade.OIDCOptions{
		Options:     *o,
		AuthOptions: opts,
		Issuer:      BaseURL + "/realms/" + Realm,
		UseNonce:    true,
		UsePKCE:     true,
	})

	if err != nil {
		return nil, err
	}
	return p, nil
}

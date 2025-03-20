package providers

import (
	"github.com/djsisson/jade"
	"golang.org/x/oauth2"
)

var (
	MicrosoftIssuer = "https://login.microsoftonline.com"
	MicrosoftScopes = []string{"openid", "profile", "email"}
)

type MicrosoftUser struct {
	Email    string `json:"email"`
	Name     string `json:"name"`
	ID       string `json:"sub"`
	UserName string `json:"preferred_username"`
}

func (m *MicrosoftUser) Claims() *jade.User {
	return &jade.User{
		ID:       m.ID,
		Issuer:   "microsoft",
		Name:     m.Name,
		Email:    m.Email,
		UserName: m.UserName,
	}
}

func NewMicrosoftProvider(Tenant string, o *jade.Options, opts ...oauth2.AuthCodeOption) (jade.Provider, error) {
	if Tenant == "" {
		Tenant = "common"
	}
	if len(o.Scopes) == 0 {
		o.Scopes = MicrosoftScopes
	}
	if len(opts) == 0 {
		opts = []oauth2.AuthCodeOption{
			jade.WithOfflineAccess(),
		}
	}

	p, err := jade.NewOIDCProvider[*MicrosoftUser](&jade.OIDCOptions{
		Options:     *o,
		Name:        "microsoft",
		AuthOptions: opts,
		Issuer:      MicrosoftIssuer + "/" + Tenant + "/v2.0",
		UseNonce:    true,
		UsePKCE:     true,
	})

	if err != nil {
		return nil, err
	}
	return p, nil
}

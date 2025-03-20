package providers

import (
	"fmt"

	"github.com/djsisson/jade"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/endpoints"
)

var (
	AmazonApiUrl = "https://api.amazon.com/user/profile"
	AmazonScopes = []string{"profile"}
)

type AmazonUser struct {
	ID    int    `json:"user_id,omitempty"`
	Email string `json:"email,omitempty"`
	Name  string `json:"name,omitempty"`
}

func (au *AmazonUser) Claims() *jade.User {
	return &jade.User{
		ID:            fmt.Sprintf("%d", au.ID),
		Issuer:        "amazon",
		Email:         au.Email,
		EmailVerified: true,
		Name:          au.Name,
	}
}

func NewAmazonProvider(o *jade.Options, opts ...oauth2.AuthCodeOption) (jade.Provider, error) {
	options := &jade.ProviderOptions{
		Options:     *o,
		Name:        "amazon",
		AuthOptions: opts,
		EndPoint:    endpoints.Amazon,
		UsePKCE:     true,
		ApiURL:      AmazonApiUrl,
	}
	if len(opts) == 0 {
		options.AuthOptions = []oauth2.AuthCodeOption{
			jade.WithOfflineAccess(),
		}
	}
	if len(o.Scopes) == 0 {
		options.Scopes = AmazonScopes
	}
	p, err := jade.NewProvider[*AmazonUser](options)
	if err != nil {
		return nil, err
	}
	return p, nil
}

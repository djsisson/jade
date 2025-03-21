package providers

import (
	"github.com/djsisson/jade"
	"golang.org/x/oauth2"
)

var (
	XApiUrl = "https://api.x.com/2/users/me"
	XScopes = []string{"users.read", "offline.access"}
)

type XUser struct {
	Id       string `json:"id"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Picture  string `json:"profile_image_url"`
	Verified bool   `json:"verified"`
	Username string `json:"username"`
}

func (x *XUser) MarshalToUser() *jade.User {
	return &jade.User{
		ID:            x.Id,
		Issuer:        "x",
		Email:         x.Email,
		EmailVerified: x.Verified,
		Name:          x.Name,
		UserName:      x.Username,
		Picture:       x.Picture,
	}
}

func NewXProvider(o *jade.Options, opts ...oauth2.AuthCodeOption) (jade.Provider, error) {
	options := &jade.ProviderOptions{
		Options:     *o,
		Name:        "x",
		AuthOptions: opts,
		EndPoint: oauth2.Endpoint{
			AuthURL:  "https://x.com/i/oauth2/authorize",
			TokenURL: "https://api.x.com/2/oauth2/token",
		},
		ApiURL:  XApiUrl,
		UsePKCE: true,
	}
	if len(opts) == 0 {
		options.AuthOptions = []oauth2.AuthCodeOption{
			jade.WithOfflineAccess(),
		}
	}
	if len(o.Scopes) == 0 {
		options.Scopes = XScopes
	}
	p, err := jade.NewProvider[*XUser](options)
	if err != nil {
		return nil, err
	}
	return p, nil
}

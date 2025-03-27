package providers

import (
	"github.com/djsisson/jade"
	"golang.org/x/oauth2"
)

var (
	TwitchScopes = []string{"openid", "user:read:email"}
	TwitchIssuer = "https://id.twitch.tv/oauth2"
)

type TwitchUser struct {
	ID       string `json:"sub,omitempty"`
	Email    string `json:"email,omitempty"`
	Username string `json:"preferred_username,omitempty"`
	Picture  string `json:"picture,omitempty"`
	Verified bool   `json:"email_verified,omitempty"`
}

func (t *TwitchUser) MarshalToUser() *jade.User {
	return &jade.User{
		ID:            t.ID,
		Issuer:        "twitch",
		Email:         t.Email,
		EmailVerified: t.Verified,
		Name:          t.Username,
		Picture:       t.Picture,
	}
}

func NewTwitchProvider(o *jade.Options, opts ...oauth2.AuthCodeOption) (jade.Provider, error) {

	if o.Name == "" {
		o.Name = "twitch"
	}
	if len(o.Scopes) == 0 {
		o.Scopes = TwitchScopes
	}
	if len(opts) == 0 {
		opts = []oauth2.AuthCodeOption{
			jade.WithOfflineAccess(),
		}
	}

	p, err := jade.NewOIDCProvider[*TwitchUser](&jade.OIDCOptions{
		Options:     *o,
		AuthOptions: opts,
		Issuer:      TwitchIssuer,
		UseNonce:    true,
	})

	if err != nil {
		return nil, err
	}
	return p, nil
}

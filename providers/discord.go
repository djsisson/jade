package providers

import (
	"github.com/djsisson/jade"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/endpoints"
)

var (
	DiscordApiUrl = "https://discord.com/api/users/@me"
	DiscordScopes = []string{"identify", "email"}
)

type DiscordUser struct {
	ID        string `json:"id,omitempty"`
	UserName  string `json:"username,omitempty"`
	Email     string `json:"email,omitempty"`
	Verified  bool   `json:"verified,omitempty"`
	Name      string `json:"name,omitempty"`
	AvatarURL string `json:"avatar,omitempty"`
	Locale    string `json:"locale,omitempty"`
}

func (d *DiscordUser) Claims() *jade.User {
	return &jade.User{
		ID:            d.ID,
		Issuer:        "discord",
		Email:         d.Email,
		EmailVerified: d.Verified,
		Name:          d.Name,
		UserName:      d.UserName,
		Picture:       d.AvatarURL,
		Locale:        d.Locale,
	}
}

func NewDiscordProvider(o *jade.Options, opts ...oauth2.AuthCodeOption) (jade.Provider, error) {
	options := &jade.ProviderOptions{
		Options:     *o,
		Name:        "discord",
		AuthOptions: opts,
		EndPoint:    endpoints.Discord,
		ApiURL:      DiscordApiUrl,
	}
	if len(opts) == 0 {
		options.AuthOptions = []oauth2.AuthCodeOption{
			jade.WithOfflineAccess(),
		}
	}
	if len(o.Scopes) == 0 {
		options.Scopes = GithubScopes
	}
	p, err := jade.NewProvider[*DiscordUser](options)
	if err != nil {
		return nil, err
	}
	return p, nil
}

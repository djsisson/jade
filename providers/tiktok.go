package providers

import (
	"github.com/djsisson/jade"
	"golang.org/x/oauth2"
)

var (
	TikTokScopes = []string{"user.info.basic", "user.info.email", "user.info.profile"}
	TikTokApiUrl = "https://open.tiktokapis.com/v2/user/info/"
)

type TikTokUser struct {
	ID       string `json:"open_id"`
	Picture  string `json:"avatar_url"`
	Username string `json:"username"`
	Name     string `json:"display_name"`
}

func (t *TikTokUser) Claims() *jade.User {
	return &jade.User{
		ID:       t.ID,
		Issuer:   "tiktok",
		Name:     t.Name,
		UserName: t.Username,
		Picture:  t.Picture,
	}
}

func NewTikTokProvider(o *jade.Options, opts ...oauth2.AuthCodeOption) (jade.Provider, error) {
	options := &jade.ProviderOptions{
		Options:     *o,
		Name:        "tiktok",
		AuthOptions: opts,
		EndPoint: oauth2.Endpoint{
			AuthURL:  "https://www.tiktok.com/v2/auth/authorize",
			TokenURL: "https://open.tiktokapis.com/v2/oauth/token",
		},
		ApiURL:  TikTokApiUrl,
		UsePKCE: true,
	}
	if len(opts) == 0 {
		options.AuthOptions = []oauth2.AuthCodeOption{
			jade.WithOfflineAccess(),
		}
	}
	if len(o.Scopes) == 0 {
		options.Scopes = TikTokScopes
	}
	p, err := jade.NewProvider[*TikTokUser](options)
	if err != nil {
		return nil, err
	}
	return p, nil
}

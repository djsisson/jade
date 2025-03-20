package providers

import (
	"github.com/djsisson/jade"
	"golang.org/x/oauth2"
)

var (
	RedditApiUrl = "https://oauth.reddit.com/api/v1/me"
	RedditScopes = []string{"identity", "read"}
)

type RedditUser struct {
	Email string `json:"email,omitempty"`
	Name  string `json:"name,omitempty"`
	ID    string `json:"id,omitempty"`
}

func (r *RedditUser) Claims() *jade.User {
	return &jade.User{
		ID:            r.ID,
		Issuer:        "reddit",
		Name:          r.Name,
		Email:         r.Email,
		EmailVerified: true,
	}
}

func NewRedditProvider(o *jade.Options, opts ...oauth2.AuthCodeOption) (jade.Provider, error) {
	options := &jade.ProviderOptions{
		Options:     *o,
		Name:        "reddit",
		AuthOptions: opts,
		EndPoint: oauth2.Endpoint{
			AuthURL:  "https://ssl.reddit.com/api/v1/authorize",
			TokenURL: "https://ssl.reddit.com/api/v1/access_token",
		},
		ApiURL: RedditApiUrl,
	}
	if len(opts) == 0 {
		options.AuthOptions = []oauth2.AuthCodeOption{
			jade.WithOfflineAccess(),
		}
	}
	if len(o.Scopes) == 0 {
		options.Scopes = GithubScopes
	}
	p, err := jade.NewProvider[*RedditUser](options)
	if err != nil {
		return nil, err
	}
	return p, nil
}

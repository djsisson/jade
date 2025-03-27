package providers

import (
	"fmt"

	"github.com/djsisson/jade"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/endpoints"
)

var (
	GithubApiUrl = "https://api.github.com"
	GithubScopes = []string{"user"}
)

type GithubUser struct {
	ID        int    `json:"id,omitempty"`
	UserName  string `json:"login,omitempty"`
	Email     string `json:"email,omitempty"`
	Name      string `json:"name,omitempty"`
	AvatarURL string `json:"avatar_url,omitempty"`
}

func (g *GithubUser) MarshalToUser() *jade.User {
	return &jade.User{
		ID:            fmt.Sprintf("%d", g.ID),
		Issuer:        "github",
		Email:         g.Email,
		EmailVerified: true,
		Name:          g.Name,
		UserName:      g.UserName,
		Picture:       g.AvatarURL,
	}
}

func NewGithubProvider(o *jade.Options, opts ...oauth2.AuthCodeOption) (jade.Provider, error) {
	if o.Name == "" {
		o.Name = "github"
	}
	options := &jade.ProviderOptions{
		Options:     *o,
		AuthOptions: opts,
		EndPoint:    endpoints.GitHub,
		ApiURL:      GithubApiUrl,
	}
	if len(opts) == 0 {
		options.AuthOptions = []oauth2.AuthCodeOption{
			jade.WithOfflineAccess(),
		}
	}
	if len(o.Scopes) == 0 {
		options.Scopes = GithubScopes
	}
	p, err := jade.NewProvider[*GithubUser](options)
	if err != nil {
		return nil, err
	}
	return p, nil
}

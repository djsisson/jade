package providers

import (
	"github.com/djsisson/jade"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/endpoints"
)

var (
	SpotifyApiUrl = "https://api.spotify.com/v1/me"
	SpotifyScopes = []string{"user-read-email"}
)

type SpotifyUser struct {
	DisplayName string             `json:"display_name"`
	Avatars     []spotifyUserImage `json:"images"`
	Email       string             `json:"email"`
	ID          string             `json:"id"`
}

type spotifyUserImage struct {
	Url    string `json:"url"`
	Height int    `json:"height"`
	Width  int    `json:"width"`
}

func (s *SpotifyUser) MarshalToUser() *jade.User {
	u := &jade.User{
		ID:            s.ID,
		Name:          s.DisplayName,
		Email:         s.Email,
		Issuer:        "spotify",
		EmailVerified: true,
	}

	if len(s.Avatars) > 0 {
		u.Picture = s.Avatars[0].Url
	}
	return u
}

func (s *SpotifyUser) NewSpotifyProvider(o *jade.Options, opts ...oauth2.AuthCodeOption) (jade.Provider, error) {
	if o.Name == "" {
		o.Name = "spotify"
	}
	options := &jade.ProviderOptions{
		Options:     *o,
		AuthOptions: opts,
		EndPoint:    endpoints.Spotify,
		ApiURL:      SpotifyApiUrl,
		UsePKCE:     true,
	}
	if len(opts) == 0 {
		options.AuthOptions = []oauth2.AuthCodeOption{
			jade.WithOfflineAccess(),
		}
	}
	if len(o.Scopes) == 0 {
		options.Scopes = SpotifyScopes
	}
	p, err := jade.NewProvider[*SpotifyUser](options)
	if err != nil {
		return nil, err
	}
	return p, nil
}

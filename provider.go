package jade

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"

	"golang.org/x/oauth2"
)

var (
	mu        sync.RWMutex
	providers = Providers{}
)

type Provider interface {
	Name() string
	AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) *AuthCode
	GetOAuthToken(code string, opts ...oauth2.AuthCodeOption) (*Token, error)
	GetUserData(ctx context.Context, token *Token) (*User, error)
	IsTokenValid(ctx context.Context, token *Token) bool
}

type Claims interface {
	Claims() *User
}

type AuthCode struct {
	Url   string
	Code  string
	Nonce string
}

type Providers map[string]Provider

// UseProviders sets the providers that can be used to authenticate with the server.
// If a provider with the same name already exists, it will be overwritten.
func UseProviders(p ...Provider) {
	mu.Lock()
	defer mu.Unlock()

	for _, provider := range p {
		providers[provider.Name()] = provider
	}
}

// GetProviders returns a map of all providers that have been registered.
// The map is keyed by the name of the provider.
func GetProviders() Providers {
	mu.RLock()
	defer mu.RUnlock()

	return providers
}

// GetProvider returns the provider with the given name.
// If no provider with the given name exists, it returns an error.
func GetProvider(name string) (Provider, error) {
	mu.RLock()
	provider := providers[name]
	mu.RUnlock()
	if provider == nil {
		return nil, fmt.Errorf("no provider for %s exists", name)
	}
	return provider, nil
}

// ClearProviders removes all registered providers from the global providers map.
func ClearProviders() {
	mu.Lock()
	defer mu.Unlock()

	providers = Providers{}
}

type provider[T Claims] struct {
	*oauth2.Config
	name        string
	authOptions []oauth2.AuthCodeOption
	apiURL      string
	useNonce    bool
	usePKCE     bool
}

// newProvider initializes a new provider instance with the given options.
// It validates the provided options and constructs an oauth2.Config with them.
// Returns a pointer to the created provider or an error if validation fails.

func NewProvider[T Claims](opts *ProviderOptions) (*provider[T], error) {
	if err := validateOptions(opts); err != nil {
		return nil, err
	}

	provider := &provider[T]{
		name:        opts.Name,
		authOptions: opts.AuthOptions,
		usePKCE:     opts.UsePKCE,
		apiURL:      opts.ApiURL,
		Config: &oauth2.Config{
			ClientID:     opts.ClientID,
			ClientSecret: opts.ClientSecret,
			RedirectURL:  opts.CallbackURL,
			Endpoint:     opts.EndPoint,
			Scopes:       opts.Scopes,
		},
	}

	return provider, nil
}

// Name returns the name of the provider, which is the unique identifier for it.
func (p *provider[T]) Name() string {
	return p.name
}

// GetOAuthToken exchanges the given authorization code for an access token.
// It returns a pointer to the received token or an error if the exchange fails.
func (p *provider[T]) GetOAuthToken(code string, opts ...oauth2.AuthCodeOption) (*Token, error) {
	tk, err := p.Exchange(context.Background(), code, opts...)
	if err != nil {
		return nil, err
	}
	return &Token{Token: tk}, nil

}

// AuthCodeURL generates a URL to the authorization server's authorization endpoint.
// It includes the specified state and any additional authorization code options.
// The provider's default auth code options are appended to the given options.

func (p *provider[T]) AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) *AuthCode {
	res := &AuthCode{}
	if p.useNonce {
		res.Nonce = oauth2.GenerateVerifier()
		opts = append(opts, WithNonce(res.Nonce))
	}
	if p.usePKCE {
		res.Code = oauth2.GenerateVerifier()
		opts = append(opts, oauth2.S256ChallengeOption(res.Code))
	}
	res.Url = p.Config.AuthCodeURL(state, append(p.authOptions, opts...)...)
	return res
}

// IsTokenValid returns true if the given token is valid and false otherwise. It
// also updates the given token with a new token if the old one is invalid and
// can be refreshed.
func (p *provider[T]) IsTokenValid(ctx context.Context, token *Token) bool {
	if token.Valid() {
		return true
	}
	_, err := p.TokenSource(ctx, token.Token).Token()
	return err == nil
}

// validateOptions checks the provided ProviderOptions for required fields.
// It returns an error if any required field is missing. The required fields are:
// Name, ClientID, ClientSecret, CallbackURL, and EndPoint URLs (AuthURL and TokenURL).

func validateOptions(opts *ProviderOptions) error {
	if opts.Name == "" {
		return fmt.Errorf("name is required")
	}
	if opts.ClientID == "" {
		return fmt.Errorf("clientID is required")
	}
	if opts.ClientSecret == "" {
		return fmt.Errorf("clientSecret is required")
	}
	if opts.CallbackURL == "" {
		return fmt.Errorf("callbackURL is required")
	}
	if opts.EndPoint.AuthURL == "" {
		return fmt.Errorf("authURL is required")
	}
	if opts.EndPoint.TokenURL == "" {
		return fmt.Errorf("tokenURL is required")
	}
	return nil
}

// makeRequest makes an HTTP GET request to the given URL with the provided
// authorization token. If the request is successful, it unmarshals the response
// body into the given destination. If the request fails, it returns an error.
// makeRequest is used to fetch user data from the provider's API.
func (p *provider[T]) makeRequest(ctx context.Context, token *oauth2.Token, url string, dst any) error {
	client := p.Client(ctx, token)
	response, err := client.Get(url)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return err
	}

	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("failed to get data: %s", response.Status)
	}

	if err := json.NewDecoder(bytes.NewReader(body)).Decode(dst); err != nil {
		return err
	}

	return nil
}

// GetUserData returns the user data associated with the given token.
// It first checks if the token is valid, returning an error if it is not.
// If the token is valid, it extracts and verifies the ID token using the
// OIDC provider's verifier. The function then extracts the user claims from
// the ID token and returns them as a jade.User object.
// If the ID token is not present, verification fails, or the claim extraction
// fails, the function returns an error.
func (p *provider[T]) GetUserData(ctx context.Context, token *Token) (*User, error) {

	if !p.IsTokenValid(ctx, token) {
		return nil, fmt.Errorf("token is not valid")
	}

	var user T
	if err := p.makeRequest(ctx, token.Token, p.apiURL, user); err != nil {
		return nil, err
	}
	return user.Claims(), nil
}

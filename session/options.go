package session

import (
	"time"

	"github.com/gorilla/sessions"
)

type JadeOptions struct {
	CookiePrefix   string
	CookieDuration time.Duration
	keyPairs       [][]byte
	Store          sessions.Store
	StateDuration  time.Duration
	JWTSecret      string
}

// WithStore sets the session store used by the JadeStore.
//
// The store is used for storing authentication state and session data.
func WithStore(store sessions.Store) JadeOptions {
	return JadeOptions{Store: store}
}

// WithCookiePrefix sets the prefix for the session cookie name.
//
// The prefix is prepended to the default "_session" suffix when generating
// the full cookie name. This allows for distinguishing between different
// session cookies within the same domain.

func WithCookiePrefix(CookiePrefix string) JadeOptions {
	return JadeOptions{CookiePrefix: CookiePrefix}
}

// WithKeyPairs sets the secure cookie key pairs used to encode and decode
// the session cookie. The key pairs are used to rotate the session cookie
// keys and to ensure that the session cookie is secure.
func WithKeyPairs(keypairs ...[]byte) JadeOptions {
	return JadeOptions{keyPairs: keypairs}
}

// WithStateDuration sets the duration for the state cookie used for OAuth2
// authorization flow. The state cookie is used to store the state of the
// authorization flow and is removed when the authorization flow is complete.
//
// The default duration is 5 minutes.
func WithStateDuration(duration time.Duration) JadeOptions {
	return JadeOptions{StateDuration: duration}
}

// WithCookieDuration sets the duration for the session cookie.
//
// This option allows customization of how long the session cookie remains valid.
// The duration is specified as a time.Duration value.
//
// The default duration is set to 30 days.

func WithCookieDuration(duration time.Duration) JadeOptions {
	return JadeOptions{CookieDuration: duration}
}

// WithJWTSecret sets the secret used for signing the JSON web token (JWT)
// that is used to store the authorization state.
//
// The secret is used to sign the JWT and to verify the JWT when it is
// received. The secret should be a secure random string and should be kept
// private.
func WithJWTSecret(secret string) JadeOptions {
	return JadeOptions{JWTSecret: secret}
}
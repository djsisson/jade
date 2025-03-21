package session

import (
	"context"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"github.com/djsisson/jade"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
)

func init() {
	gob.Register(jade.Token{})
	gob.Register(jade.User{})
}

const (
	defaultCookiePrefix   = "jade"
	defaultCookieDuration = 30 * 24 * time.Hour
	defaultSecret         = "Cookie Secret"
	defaultStateDuration  = 5 * time.Minute
	defaultJWTSecret      = "jwt secret"
)

type JadeStore interface {
	BeginAuth(r *http.Request, w http.ResponseWriter, provider, redirect string) error
	CompleteAuth(r *http.Request, w http.ResponseWriter) error
	GetUserData(r *http.Request, w http.ResponseWriter) (*jade.User, error)
	GetAccessToken(r *http.Request) (string, error)
	DeleteSession(r *http.Request, w http.ResponseWriter, redirect string) error
}

type jadeStore struct {
	st            sessions.Store
	cookieName    string
	stateDuration time.Duration
	jwtSecret     string
}

type claims struct {
	jwt.RegisteredClaims
	State    string
	Provider string
	Redirect string
}

// newStore creates a new instance of JadeStore from the given options.
//
// It takes the given sessions.Store and prefix and creates a new
// instance of JadeStore. The cookie name is set to the given prefix
// plus "_session". The state duration is set to the given duration.
func newStore(opts *JadeOptions) JadeStore {
	js := &jadeStore{
		st:            opts.Store,
		cookieName:    opts.CookiePrefix + "_session",
		stateDuration: opts.StateDuration,
	}
	return js
}

// NewJadeStore initializes a JadeStore with the specified options.
//
// It accepts multiple JadeOptions, allowing customization of the store's behavior.
// The options can include a custom session store, cookie prefix, cookie duration,
// state duration, JWT secret, and key pairs. Default values are used for any
// unspecified options. If no session store is provided, a new cookie store is
// created with the provided or default key pairs. The function returns a configured
// instance of JadeStore.

func NewJadeStore(options ...JadeOptions) JadeStore {
	opts := &JadeOptions{
		CookiePrefix:   defaultCookiePrefix,
		CookieDuration: defaultCookieDuration,
		StateDuration:  defaultStateDuration,
		JWTSecret:      defaultJWTSecret,
	}
	for _, o := range options {
		if o.Store != nil {
			opts.Store = o.Store
		}
		if o.CookiePrefix != "" {
			opts.CookiePrefix = o.CookiePrefix
		}
		if o.CookieDuration > 0 {
			opts.CookieDuration = o.CookieDuration
		}
		if o.StateDuration > 0 {
			opts.StateDuration = o.StateDuration
		}
		if o.JWTSecret != "" {
			opts.JWTSecret = o.JWTSecret
		}
		if len(o.keyPairs) > 0 {
			opts.keyPairs = append(opts.keyPairs, o.keyPairs...)
		}
	}
	if len(opts.keyPairs) == 0 {
		opts.keyPairs = [][]byte{[]byte(defaultSecret)}
	}
	if opts.Store == nil {
		st := sessions.NewCookieStore(opts.keyPairs...)
		st.Options = &sessions.Options{
			Path:     "/",
			MaxAge:   int(opts.CookieDuration.Seconds()),
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
			Secure:   true,
		}
		opts.Store = st
	}

	return newStore(opts)
}

// DeleteSession removes the session cookie by setting it to expire immediately.
//
// This function first retrieves the session from the store, then sets the
// MaxAge to -1, and then saves the session back to the store. This results
// in the session cookie being removed from the client.
//
// If the redirect argument is not empty, the client is redirected to the
// given URL after the session cookie is removed.
//
// This function returns an error if the session cannot be retrieved or saved.
func (st *jadeStore) DeleteSession(r *http.Request, w http.ResponseWriter, redirect string) error {
	s, err := st.st.Get(r, st.cookieName)
	if err != nil {
		return err
	}
	s.Options.MaxAge = -1
	s.Values = make(map[any]any)
	err = st.st.Save(r, w, s)
	if err != nil {
		return err
	}
	if redirect != "" {
		http.Redirect(w, r, redirect, http.StatusSeeOther)
	}
	return nil
}

// BeginAuth starts the authentication flow with the given provider.
// It first tries to verify if the user is already authenticated by checking
// if there is a valid token in the session. If so, it redirects the user to the
// redirect URL. If not, it generates a state token and saves it to the session,
// then redirects the user to the authorization URL for the provider.
//
// If there is an existing token, but no refresh token, it sets the force approval prompt option.
// The user is then redirected to the authorization URL.
func (st *jadeStore) BeginAuth(r *http.Request, w http.ResponseWriter, provider, redirect string) error {

	session, err := st.getSessionWithId(r)
	if err != nil {
		return err
	}
	p, err := jade.GetProvider(provider)
	if err != nil {
		return err
	}

	hash := hashSessionId(session.ID)
	state, err := st.signJWT(&claims{
		State:    hash,
		Provider: provider,
		Redirect: redirect,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(st.stateDuration)),
		},
	})
	if err != nil {
		return err
	}

	authCode := p.AuthCodeURL(state)

	session.Values["pkce"] = authCode.Code
	session.Values["nonce"] = authCode.Nonce

	err = st.st.Save(r, w, session)
	if err != nil {
		return err
	}
	http.Redirect(w, r, authCode.Url, http.StatusSeeOther)
	return nil
}

// CompleteAuth handles the callback from the OAuth provider after the user has
// granted access.
//
// It first redirects the client to itself with a query parameter "redirected"
// set to "true". This is to ensure the session cookie can be read by the
// callback handler, as it can't be read when samesite is strict.
//
// Once redirected back, it verifies the state parameter and extracts the
// authorization code and provider name from the query parameters.
//
// It then uses the authorization code to obtain an access token, and uses the
// access token to fetch the user data from the provider.
//
// Finally, it saves the token and user data to the session and redirects the
// client to the redirect URL if given.
//
// Any errors encountered during this process are returned as an error.
func (st *jadeStore) CompleteAuth(r *http.Request, w http.ResponseWriter) error {

	sess, err := st.getSession(r)
	if err != nil {
		// if we are here then we can't read the cookie (due to samesite strict, so we need to force a refresh to same location.)
		redir := r.FormValue("redirected")
		if redir != "true" {
			// make sure we only redirect once by adding redirected param
			completeAuthRedirect(r, w)
			return nil
		}
		// if we are here, then there is no cookie set and need to abort the request
		return err
	}

	code := r.FormValue("code")
	state := r.FormValue("state")
	if code == "" || state == "" {
		return fmt.Errorf("invalid request")
	}

	claims, err := st.verifyJWT(state)
	if err != nil {
		return err
	}

	if hashSessionId(sess.ID) != claims.State {
		return fmt.Errorf("invalid state")
	}

	providerInstance, err := jade.GetProvider(claims.Provider)
	if err != nil {
		return err
	}

	opts := []oauth2.AuthCodeOption{}
	pkce, ok := sess.Values["pkce"].(string)
	if ok && pkce != "" {
		opts = append(opts, oauth2.VerifierOption(pkce))
	}

	token, err := providerInstance.GetOAuthToken(code, opts...)
	if err != nil {
		return err
	}

	nonce, ok := sess.Values["nonce"].(string)
	if ok && nonce != "" {
		if token.Nonce != nonce {
			return fmt.Errorf("invalid nonce")
		}
	}

	u, err := providerInstance.GetUserData(r.Context(), token)
	if err != nil {
		return err
	}

	delete(sess.Values, "pkce")
	delete(sess.Values, "nonce")

	sess.Values["user"] = u
	sess.Values["token"] = token
	sess.Values["provider"] = claims.Provider
	sess.Options.Secure = r.TLS != nil
	err = st.st.Save(r, w, sess)
	if err != nil {
		return err
	}

	if claims.Redirect != "" {
		http.Redirect(w, r, claims.Redirect, http.StatusSeeOther)
	}

	return nil
}

// GetUserData returns the user data for the user in the current session.
//
// If the user is not authenticated, it returns an error.
//
// If the user is authenticated, it first checks if the session already has a valid user data.
// If it does, it simply returns that user data.
//
// If it does not have a valid user data, it uses the stored access token to fetch the user data
// from the provider, and stores the user data in the session.
//
// If the access token is expired, it first tries to refresh the token using the stored refresh token.
// If the refresh token is also expired or invalid, it returns an error.
// If the refresh token is valid, it uses the new access token to fetch the user data and stores it in the session.
func (st *jadeStore) GetUserData(r *http.Request, w http.ResponseWriter) (u *jade.User, err error) {

	session, err := st.getSession(r)

	if err != nil {
		return nil, err
	}

	defer func() {
		if session.IsNew {
			st.st.Save(r, w, session)
		}
	}()

	token, ok := session.Values["token"].(jade.Token)
	if !ok {
		err = fmt.Errorf("no token in session")
		return
	}

	providerName, ok := session.Values["provider"].(string)
	if !ok {
		err = fmt.Errorf("no provider in session")
		return
	}

	provider, err := jade.GetProvider(providerName)
	if err != nil {
		return
	}

	accessToken := token.AccessToken

	if !provider.IsTokenValid(r.Context(), &token) {
		return nil, fmt.Errorf("token is not valid")
	}

	if token.AccessToken != accessToken {
		session.Values["token"] = token
		session.IsNew = true
	}

	user, ok := session.Values["user"].(*jade.User)
	if ok {
		return user, nil
	}

	u, err = provider.GetUserData(context.Background(), &token)
	if err != nil {
		return nil, err
	}

	session.Values["user"] = u
	session.IsNew = true

	return u, nil
}

// GetAccessToken returns the access token associated with the current session.
// If the session does not contain a valid access token, it returns an error.
func (st *jadeStore) GetAccessToken(r *http.Request) (string, error) {
	session, err := st.getSession(r)
	if err != nil {
		return "", err
	}
	token, ok := session.Values["token"].(jade.Token)
	if !ok {
		return "", fmt.Errorf("no token in session")
	}
	if !token.Valid() {
		return "", fmt.Errorf("token is not valid")
	}
	return token.AccessToken, nil
}

// getSession retrieves a session from the store using the given request.
// If the session is not found or does not contain an ID, it returns an error.
// Otherwise, it sets the session ID and IsNew properties and returns the session.
func (st *jadeStore) getSession(r *http.Request) (*sessions.Session, error) {
	session, err := st.st.Get(r, st.cookieName)
	if err != nil {
		return nil, err
	}
	id, ok := session.Values["id"].(string)
	if !ok || id == "" {
		return nil, fmt.Errorf("no id in session")
	}
	session.IsNew = false
	session.ID = id
	return session, nil
}

// getSessionWithId returns a session with the ID from the session store, or
// generates a new session with a new ID and saves it to the session store.
func (st *jadeStore) getSessionWithId(r *http.Request) (*sessions.Session, error) {
	session, err := st.getSession(r)

	if err == nil {
		return session, nil
	}

	newUUID, err := uuid.NewV7()
	if err != nil {
		return nil, err
	}
	session.ID = newUUID.String()
	session.Values["id"] = session.ID
	session.IsNew = true

	return session, nil
}

// signJWT creates a signed JWT containing the given claims.
//
// It uses the secret key associated with the store to sign the JWT.
// The resulting JWT is returned as a string, or an error if there was a problem signing the JWT.
func (st *jadeStore) signJWT(c *claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, c)

	return token.SignedString([]byte(st.jwtSecret))
}

// verifyJWT parses and verifies a JSON Web Token (JWT) using the store's secret key.
//
// It first ensures that the token is signed with the HMAC signing method and then
// uses the store's JWT secret to validate the token signature. If the token is valid
// and not expired, it extracts the claims from the token.
//
// Parameters:
//   tokenString - the JWT string to be verified.
//
// Returns:
//   claims - the extracted claims from the JWT if the token is valid.
//   error - an error if the token is invalid, expired, or if there is an issue with parsing or verification.

func (st *jadeStore) verifyJWT(tokenString string) (*claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &claims{}, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(st.jwtSecret), nil
	})
	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*claims); ok && token.Valid && claims.ExpiresAt.Time.After(time.Now()) {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}

// hashSessionId generates a SHA-256 hash of the provided session ID string.
//
// The function creates a new SHA-256 hasher, writes the session ID to it,
// and returns the resulting hash as a hexadecimal-encoded string.
//
// Parameters:
//   id - the session ID to be hashed.
//
// Returns:
//   a hexadecimal-encoded string representing the SHA-256 hash of the session ID.

func hashSessionId(id string) string {
	h := sha256.New()
	h.Write([]byte(id))
	return hex.EncodeToString(h.Sum(nil))
}

// completeAuthRedirect is a helper function that redirects the request to itself
// with a query parameter "redirected" set to "true". This is to ensure the session
// cookie can be read by the callback handler, as it can't be read when samesite is
// strict.
//
// It takes a request and response writer as parameters, and returns an error if
// the request is invalid (i.e. it is missing the code or state query parameters).
//
// The function first checks if the request has the code and state query parameters.
// If either of them is missing, it returns an error.
//
// If the request is valid, it redirects the request to itself with the
// "redirected" query parameter set to "true".
func completeAuthRedirect(r *http.Request, w http.ResponseWriter) error {
	code := r.FormValue("code")
	state := r.FormValue("state")
	if code == "" || state == "" {
		return fmt.Errorf("invalid request: missing code or state")
	}

	url := r.URL
	if url == nil {
		return fmt.Errorf("invalid request: cannot get URL")
	}

	query := url.Query()
	query.Set("code", code)
	query.Set("state", state)
	query.Set("redirected", "true")
	url.RawQuery = query.Encode()

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)

	_, err := fmt.Fprintf(w, `
			<html>
			<head>
				<meta http-equiv="refresh" content="0; url=%s">
			</head>
			<body></body>
			</html>
		`, url.String())
	return err
}

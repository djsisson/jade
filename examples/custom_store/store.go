package main

import (
	"context"
	"net/http"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
)

const (
	sessionIDLen  = 32
	defaultMaxAge = 60 * 60 * 24 * 30
	defaultPath   = "/"
	defaultKey    = "secret"
)

type CustomStore interface {
	Get(r *http.Request, name string) (*sessions.Session, error)
	Save(r *http.Request, w http.ResponseWriter, session *sessions.Session) error
	New(r *http.Request, name string) (*sessions.Session, error)
	MaxAge(age int)
	MaxLength(l int)
	Cleanup()
	periodicCleanup(c context.Context, interval time.Duration)
}

type customStore struct {
	repo        SessionRepository
	Codecs      []securecookie.Codec
	SessionOpts *sessions.Options
}

// NewCustomStore returns a new instance of CustomStore.
//
// The CustomStore interface is implemented by the customStore type, which stores
// session data in a database. The data is encrypted with a secure cookie.
//
// The NewCustomStore function takes a context.Context, a SessionRepository,
// and a variable number of []byte values containing the key pairs to use for
// encrypting the session data. If no key pairs are given, the default key
// "secret" is used.
//
// The session options are set to:
//
//	Path: /
//	MaxAge: 30 days
//	HttpOnly: true
//	SameSite: http.SameSiteStrictMode
//	Secure: true
//
// The session cleanup function is called with a period of 1 hour.
func NewCustomStore(ctx context.Context, repo SessionRepository, keyPairs ...[]byte) CustomStore {
	if len(keyPairs) == 0 {
		keyPairs = [][]byte{[]byte(defaultKey)}
	}
	s := &customStore{
		repo:   repo,
		Codecs: securecookie.CodecsFromPairs(keyPairs...),
		SessionOpts: &sessions.Options{
			Path:     "/",
			MaxAge:   defaultMaxAge,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
			Secure:   true,
		},
	}
	s.MaxAge(defaultMaxAge)
	go s.periodicCleanup(ctx, time.Hour)
	return s
}

// Get implements the sessions.Store Get method.
//
// It gets the session from the sessions Registry using the given name.
func (s *customStore) Get(r *http.Request, name string) (*sessions.Session, error) {
	return sessions.GetRegistry(r).Get(s, name)
}

// New implements the sessions.Store New method.
//
// It creates a new session with the given name, copying the session options
// from the custom store. If a session with the same name exists in the
// request, the existing session ID and values are copied to the new session.
func (s *customStore) New(r *http.Request, name string) (*sessions.Session, error) {
	sess := sessions.NewSession(s, name)
	opts := *s.SessionOpts
	sess.Options = &opts
	sess.IsNew = true
	existingSession := s.getSessionFromCookie(r, sess.Name())
	if existingSession != nil {
		if err := securecookie.DecodeMulti(sess.Name(), existingSession.Value, &sess.Values, s.Codecs...); err == nil {
			sess.ID = existingSession.Key
			sess.IsNew = false
		}
	}
	return sess, nil
}

// Save implements the sessions.Store Save method.
//
// It saves the given session to the underlying repository. If the session's
// MaxAge is negative, it deletes the session from the repository and sets
// the session cookie to expire immediately. If the session's MaxAge is
// non-negative, it saves the session to the repository and sets the session
// cookie to expire at the given time.
func (s *customStore) Save(r *http.Request, w http.ResponseWriter, session *sessions.Session) error {
	existingSession := s.getSessionFromCookie(r, session.Name())
	if session.Options.MaxAge < 0 {
		if existingSession != nil {
			if err := s.repo.DeleteSession(session.ID); err != nil {
				return err
			}
		}
		http.SetCookie(w, sessions.NewCookie(session.Name(), "", session.Options))
		return nil
	}

	currentTime := time.Now()
	expirationTime := currentTime.Add(time.Second * time.Duration(session.Options.MaxAge)).Unix()

	encodedData, err := securecookie.EncodeMulti(session.Name(), session.Values, s.Codecs...)
	if err != nil {
		return err
	}

	if existingSession == nil  {
		newSession := &Session{
			Key:       session.ID,
			Value:     encodedData,
			ExpiresAt: expirationTime,
		}
		if err := s.repo.CreateSession(newSession); err != nil {
			return err
		}
	} else {
		existingSession.Value = encodedData
		existingSession.ExpiresAt = expirationTime
		if err := s.repo.UpdateSession(existingSession); err != nil {
			return err
		}
	}

	encodedID, err := securecookie.EncodeMulti(session.Name(), session.ID, s.Codecs...)
	if err != nil {
		return err
	}

	http.SetCookie(w, sessions.NewCookie(session.Name(), encodedID, session.Options))
	return nil
}

// getSessionFromCookie retrieves the session from the given cookie value.
//
// It first attempts to retrieve the session ID from the given cookie value.
// If the session ID is not found, it returns nil.
//
// If the session ID is found, it attempts to retrieve the session from
// the repository using the given session ID. If the session does not
// exist, it returns nil.
//
// If the session is found, it returns the session.
func (s *customStore) getSessionFromCookie(r *http.Request, name string) *Session {
	cookie, err := r.Cookie(name)
	if err != nil {
		return nil
	}

	var sessionID string
	if err := securecookie.DecodeMulti(name, cookie.Value, &sessionID, s.Codecs...); err != nil {
		return nil
	}

	session, err := s.repo.GetSession(sessionID)
	if err != nil {
		return nil
	}

	return session
}

// MaxAge sets the maximum age (in seconds) of the session cookie.
//
// This is a convenience method to set the MaxAge field of the SessionOpts
// and of all SecureCookie codecs in the Codecs slice.
func (s *customStore) MaxAge(age int) {
	s.SessionOpts.MaxAge = age
	for _, codec := range s.Codecs {
		if sc, ok := codec.(*securecookie.SecureCookie); ok {
			sc.MaxAge(age)
		}
	}
}

// MaxLength sets the maximum length of the session value that can be stored in the cookie.
// This method updates the MaxLength field for all SecureCookie codecs in the Codecs slice.
// It ensures that the session data does not exceed the specified length.

func (s *customStore) MaxLength(l int) {
	for _, c := range s.Codecs {
		if codec, ok := c.(*securecookie.SecureCookie); ok {
			codec.MaxLength(l)
		}
	}
}

// Cleanup removes all expired sessions from the underlying repository.
//
// It is a convenience method that simply calls ClearExpiredSessions on the
// underlying repository.
func (s *customStore) Cleanup() {
	s.repo.ClearExpiredSessions()
}

// periodicCleanup periodically calls the Cleanup method to remove expired sessions.
//
// This function starts a ticker that triggers at the specified interval, calling the
// Cleanup method each time to clear expired sessions from the underlying repository.
//
// It runs indefinitely until the context is canceled, at which point it stops the
// ticker and returns.
//
// Parameters:
//  - ctx: The context that controls the cancellation of the periodic cleanup.
//  - interval: The duration between consecutive cleanup executions.

func (s *customStore) periodicCleanup(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.Cleanup()
		case <-ctx.Done():
			return
		}
	}
}

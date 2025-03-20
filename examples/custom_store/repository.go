package main

import (
	"database/sql"
	"time"
)

type Session struct {
	ID        int
	Key       string
	Value     string
	ExpiresAt int64
}

type SessionRepository interface {
	CreateSession(s *Session) error
	GetSession(key string) (*Session, error)
	DeleteSession(key string) error
	UpdateSession(s *Session) error
	ClearExpiredSessions() error
}

type sessionRepository struct {
	db *sql.DB
}

// NewSessionRepository returns a new SessionRepository backed by the given SQL
// database connection.
func NewSessionRepository(db *sql.DB) SessionRepository {
	return &sessionRepository{db}
}

// CreateSession saves the given session to the database. It returns an error if
// the session cannot be saved. The ID field of the session is set to the
// automatically assigned ID from the database.
func (r *sessionRepository) CreateSession(s *Session) error {
	res, err := r.db.Exec("INSERT INTO sessions (key, value, expires_at) VALUES (?, ?, ?)", s.Key, s.Value, s.ExpiresAt)
	if err != nil {
		return err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return err
	}
	s.ID = int(id)
	return nil
}

// GetSession retrieves the session with the given key from the database.
// If the session does not exist, it returns a nil session and an error.
func (r *sessionRepository) GetSession(key string) (*Session, error) {
	var s Session
	err := r.db.QueryRow("SELECT id, key, value, expires_at FROM sessions WHERE key = ?", key).Scan(&s.ID, &s.Key, &s.Value, &s.ExpiresAt)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// DeleteSession removes the session with the given key from the database.
// It returns an error if the session cannot be deleted.
func (r *sessionRepository) DeleteSession(key string) error {
	_, err := r.db.Exec("DELETE FROM sessions WHERE key = ?", key)
	return err
}

// UpdateSession updates the session with the given key in the database.
// It returns an error if the session cannot be updated.
func (r *sessionRepository) UpdateSession(s *Session) error {
	_, err := r.db.Exec("UPDATE sessions SET value = ?, expires_at = ? WHERE key = ?", s.Value, s.ExpiresAt, s.Key)
	return err
}

// ClearExpiredSessions removes all expired sessions from the database. It
// returns an error if the removal fails.
func (r *sessionRepository) ClearExpiredSessions() error {
	_, err := r.db.Exec("DELETE FROM sessions WHERE expires_at < ?", time.Now().Unix())
	return err
}

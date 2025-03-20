package main

import (
	"database/sql"

	_ "modernc.org/sqlite"
)

// NewDB opens a database connection and migrates the database to the latest
// version.  It returns the database connection and any error that occurred.
func NewDB(dsn string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	err = Migrate(db)
	if err != nil {
		return nil, err
	}
	return db, nil
}

// Migrate runs the database migrations for the given database connection.
//
// It returns an error if anything goes wrong.
func Migrate(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS sessions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			key TEXT NOT NULL,
			value TEXT NOT NULL,
			expires_at INTEGER
	);
	
		CREATE INDEX IF NOT EXISTS sessions_key_idx ON sessions (key);
		CREATE INDEX IF NOT EXISTS sessions_expires_at_idx ON sessions (expires_at);
	`)
	return err
}

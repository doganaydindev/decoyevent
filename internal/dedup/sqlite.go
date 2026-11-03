package dedup

import (
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// Apply records id in the SQLite database at path and then calls after.
// The write lock is held across after. If after returns an error, the sighting is not saved.
func Apply(path, id string, window time.Duration, clock Clock, after func(Result) error) (Result, error) {
	if clock == nil {
		clock = systemClock{}
	}
	if window <= 0 {
		window = 24 * time.Hour
	}
	db, err := open(path)
	if err != nil {
		return Result{}, err
	}
	defer db.Close()

	tx, err := db.Begin()
	if err != nil {
		return Result{}, err
	}
	defer tx.Rollback()

	res, err := observeTx(tx, id, window, clock.Now().UTC())
	if err != nil {
		return Result{}, err
	}
	if after != nil {
		if err := after(res); err != nil {
			return Result{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return Result{}, err
	}
	return res, nil
}

func open(path string) (*sql.DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	dsn := url.URL{
		Scheme:   "file",
		Path:     filepath.ToSlash(abs),
		RawQuery: "_txlock=immediate&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)",
	}
	db, err := sql.Open("sqlite", dsn.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS sightings (
		id TEXT PRIMARY KEY,
		count INTEGER NOT NULL,
		first TEXT NOT NULL,
		last TEXT NOT NULL
	)`); err != nil {
		db.Close()
		return nil, err
	}
	if err := os.Chmod(abs, 0o600); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func observeTx(tx *sql.Tx, id string, window time.Duration, now time.Time) (Result, error) {
	now = now.UTC()
	cutoff := now.Add(-window).Format(time.RFC3339)
	if _, err := tx.Exec(`DELETE FROM sightings WHERE last < ?`, cutoff); err != nil {
		return Result{}, err
	}
	var count int64
	var first string
	err := tx.QueryRow(`SELECT count, first FROM sightings WHERE id = ?`, id).Scan(&count, &first)
	if err == sql.ErrNoRows {
		stamp := now.Format(time.RFC3339)
		if _, err := tx.Exec(`INSERT INTO sightings (id, count, first, last) VALUES (?, 1, ?, ?)`, id, stamp, stamp); err != nil {
			return Result{}, err
		}
		return Result{Status: StatusAccepted, Count: 1, First: now, Last: now}, nil
	}
	if err != nil {
		return Result{}, err
	}
	seen, err := time.Parse(time.RFC3339, first)
	if err != nil {
		return Result{}, fmt.Errorf("state %s first: %w", id, err)
	}
	if _, err := tx.Exec(`UPDATE sightings SET count = count + 1, last = ? WHERE id = ?`, now.Format(time.RFC3339), id); err != nil {
		return Result{}, err
	}
	return Result{Status: StatusDuplicate, Count: uint64(count + 1), First: seen.UTC(), Last: now}, nil
}

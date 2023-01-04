package passwordless

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
)

type Session struct {
	TokenHash string
	UID       string
	Expires   time.Time
	Created   time.Time
}

// SQLiteStore is a Store that keeps tokens in SQLite
type SQLiteStore struct {
	db *sql.DB
	// tableName for session table
	tableName string
	// dateFormat for colExpires timestamp
	dateFormat string
}

const TableName = "session"

// "Date And Time Functions of SQLite are capable of storing...
// TEXT as ISO8601 strings ("YYYY-MM-DD HH:MM:SS.SSS")"
// https://www.sqlite.org/datatype3.html
const DateFormatISO8601 = "2006-01-02T15:04:05Z"

// NewSQLiteStore creates and returns a new SQLiteStore
func NewSQLiteStore(db *sql.DB, tableName string) (store *SQLiteStore, err error) {
	if db == nil {
		return store, errors.WithStack(ErrDBConnectionNotValid)
	}
	if tableName == "" {
		tableName = TableName
	}
	return &SQLiteStore{
		db:         db,
		tableName:  tableName,
		dateFormat: DateFormatISO8601,
	}, nil
}

// Store a generated token in SQLite for a user
func (s SQLiteStore) Store(ctx context.Context, token, uid string, ttl time.Duration) (err error) {
	query := fmt.Sprintf(
		`insert into %s (uid, token, expires, created) values (:values)
on conflict(uid) do update set 
token = excluded.token, 
expires = excluded.expires`,
		s.tableName)

	hashedToken, err := bcrypt.GenerateFromPassword(
		[]byte(token), bcrypt.DefaultCost)
	if err != nil {
		return errors.WithStack(err)
	}

	values := make([]interface{}, 0, 1)
	row := make([]interface{}, 4)
	row[0] = uid
	row[1] = hashedToken
	row[2] = time.Now().UTC().Add(ttl).Format(s.dateFormat)
	row[3] = time.Now().UTC().Format(s.dateFormat)
	values = append(values, row)

	query, _, err = sqlx.Named(query, map[string]interface{}{
		"values": row,
	})
	if err != nil {
		return errors.WithStack(err)
	}

	query, args, err := sqlx.In(query, values...)
	if err != nil {
		return errors.WithStack(err)
	}

	_, err = s.db.Exec(query, args...)
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

// Exists checks to see if a token exists
func (s SQLiteStore) Exists(ctx context.Context, uid string) (
	exists bool, expires time.Time, err error) {

	session, err := s.getSessionByUID(uid)
	if err != nil {
		return false, expires, errors.WithStack(err)
	}

	// Check token expiry
	now := time.Now().UTC().Unix()
	if now > session.Expires.Unix() {
		return false, expires, errors.WithStack(ErrTokenExpired)
	}

	return true, session.Expires, nil
}

// Verify checks to see if a token exists and is valid for a user
func (s SQLiteStore) Verify(ctx context.Context, token, uid string) (
	valid bool, err error) {

	session, err := s.getSessionByUID(uid)
	if err != nil {
		return false, errors.WithStack(err)
	}

	// Check token expiry
	now := time.Now().UTC().Unix()
	if now > session.Expires.Unix() {
		return false, errors.WithStack(ErrTokenExpired)
	}

	// Compare token hash
	err = bcrypt.CompareHashAndPassword(
		[]byte(session.TokenHash), []byte(token))
	if err != nil {
		return false, errors.WithStack(ErrTokenNotValid)
	}

	return true, nil
}

// Delete removes a key from the store
func (s SQLiteStore) Delete(ctx context.Context, uid string) error {
	return errors.Errorf("TODO Delete")
}

func (s SQLiteStore) getSessionByUID(uid string) (session Session, err error) {
	rows, err := s.db.Query(fmt.Sprintf(
		"select token, expires, created from %s where uid = ?",
		s.tableName), uid)
	if err != nil {
		return session, errors.WithStack(err)
	}
	defer rows.Close()
	var token string
	var expires string
	var created string
	if rows.Next() {
		err = rows.Scan(&token, &expires, &created)
		if err != nil {
			return session, errors.WithStack(err)
		}
	} else {
		return session, errors.WithStack(ErrTokenNotFound)
	}
	err = rows.Err()
	if err != nil {
		return session, errors.WithStack(err)
	}
	session.TokenHash = token
	session.UID = uid
	session.Expires, err = time.Parse(DateFormatISO8601, expires)
	if err != nil {
		return session, errors.WithStack(err)
	}
	session.Created, err = time.Parse(DateFormatISO8601, created)
	if err != nil {
		return session, errors.WithStack(err)
	}
	return session, nil
}

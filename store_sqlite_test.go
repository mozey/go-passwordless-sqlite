package passwordless

import (
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
)

func createDB(testName string) (db *sql.DB, err error) {
	dbPath := fmt.Sprintf("./%s.db", testName)
	err = os.Remove(dbPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Ignore
		} else {
			return db, errors.WithStack(err)
		}
	}
	db, err = sql.Open("sqlite3", dbPath)
	if err != nil {
		return db, errors.WithStack(err)
	}
	_, err = db.Exec(`create table session (
	uid string primary key,
	token varchar(255) not null,
	expires datetime not null,
	created datetime not null
);`)
	if err != nil {
		return db, errors.WithStack(err)
	}
	return db, nil
}

func TestSQLiteStoreExists(t *testing.T) {
	db, err := createDB(t.Name())
	require.NoError(t, err)
	s, err := NewSQLiteStore(db, "")
	require.NoError(t, err)
	require.NotNil(t, s)

	b, exp, err := s.Exists(nil, "uid")
	require.Error(t, err)
	require.False(t, b)
	require.True(t, exp.IsZero())

	err = s.Store(nil, "", "uid", -time.Hour)
	require.NoError(t, err)
	b, exp, err = s.Exists(nil, "uid")
	require.Error(t, err)
	require.False(t, b)
	require.True(t, exp.IsZero())

	err = s.Store(nil, "", "uid", time.Hour)
	require.NoError(t, err)
	b, exp, err = s.Exists(nil, "uid")
	require.NoError(t, err)
	require.True(t, b)
	require.False(t, exp.IsZero())
}

func TestSQLiteStoreVerify(t *testing.T) {
	db, err := createDB(t.Name())
	require.NoError(t, err)
	s, err := NewSQLiteStore(db, "")
	require.NoError(t, err)
	require.NotNil(t, s)

	// Token doesn't exist
	b, err := s.Verify(nil, "bad_token", "uid")
	require.False(t, b)
	require.Error(t, err)

	// Token expired
	err = s.Store(nil, "", "uid", -time.Hour)
	require.NoError(t, err)
	b, err = s.Verify(nil, "bad_token", "uid")
	require.False(t, b)
	require.Equal(t, ErrTokenExpired.Error(), err.Error())

	// Token wrong
	err = s.Store(nil, "token", "uid", time.Hour)
	require.NoError(t, err)
	b, err = s.Verify(nil, "bad_token", "uid")
	require.False(t, b)
	require.NoError(t, err)

	// Token correct
	b, err = s.Verify(nil, "token", "uid")
	require.True(t, b)
	require.NoError(t, err)
}

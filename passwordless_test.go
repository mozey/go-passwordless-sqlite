package passwordless

import (
	"fmt"
	"testing"
	"time"

	"context"

	"github.com/stretchr/testify/require"
)

type testTransport struct {
	token     string
	recipient string
	err       error
}

func (t *testTransport) Send(ctx context.Context, token, user, recipient string) error {
	t.token = token
	t.recipient = recipient
	return t.err
}

type testGenerator struct {
	token string
	err   error
}

func (g testGenerator) Generate(ctx context.Context) (string, error) {
	return g.token, g.err
}

func (g testGenerator) Sanitize(ctx context.Context, s string) (string, error) {
	return s, nil
}

func TestPasswordless(t *testing.T) {
	db, err := createDB(t.Name())
	require.NoError(t, err)
	store, err := NewSQLiteStore(db, "")
	require.NoError(t, err)
	p := New(store)

	tt := &testTransport{}
	tg := &testGenerator{token: "1337"}
	s := p.SetTransport("test", tt, tg, 5*time.Minute)

	// Check transports match those set
	require.Equal(t, map[string]Strategy{"test": s}, p.ListStrategies(nil))
	if s0, err := p.GetStrategy(nil, "test"); err != nil {
		require.NoError(t, err)
	} else {
		require.Equal(t, s, s0)
	}

	// Check returned token is as expected
	require.NoError(t, p.RequestToken(nil, "test", "uid", "recipient"))
	require.Equal(t, tt.token, tg.token)
	require.Equal(t, tt.recipient, "recipient")

	// Check invalid token is rejected
	v, err := p.VerifyToken(nil, "uid", "badtoken")
	require.NoError(t, err)
	require.False(t, v)

	// Verify token
	v, err = p.VerifyToken(nil, "uid", tg.token)
	require.NoError(t, err)
	require.True(t, v)
}

type testStrategy struct {
	SimpleStrategy
	valid bool
}

func (s testStrategy) Valid(c context.Context) bool {
	return s.valid
}

func TestPasswordlessFailures(t *testing.T) {
	db, err := createDB(t.Name())
	require.NoError(t, err)
	store, err := NewSQLiteStore(db, "")
	require.NoError(t, err)
	p := New(store)

	_, err = p.GetStrategy(nil, "madeup")
	require.Equal(t, err, ErrUnknownStrategy)

	err = p.RequestToken(nil, "madeup", "", "")
	require.Equal(t, err, ErrUnknownStrategy)

	p.SetStrategy("unfriendly", testStrategy{valid: false})

	err = p.RequestToken(nil, "unfriendly", "", "")
	require.Equal(t, err, ErrNotValidForContext)
}

func TestRequestToken(t *testing.T) {
	// Test Generate()
	require.EqualError(t, RequestToken(nil, nil, &mockStrategy{
		generate: func(c context.Context) (string, error) {
			return "", fmt.Errorf("refused generate")
		},
	}, "", ""), "refused generate", "Generate() error should propagate")

	// Test Send()
	require.EqualError(t, RequestToken(nil, &mockTokenStore{
		store: func(ctx context.Context, token, uid string, ttl time.Duration) error {
			return nil
		},
	}, &mockStrategy{
		generate: func(c context.Context) (string, error) {
			return "", nil
		},
		send: func(c context.Context, token, user, recipient string) error {
			return fmt.Errorf("refused send")
		},
	}, "", ""), "refused send", "Send() error should propagate")

	// Test Store()
	err := RequestToken(nil, &mockTokenStore{
		store: func(ctx context.Context, token, uid string, ttl time.Duration) error {
			return fmt.Errorf("refused store")
		},
	}, &mockStrategy{
		generate: func(c context.Context) (string, error) {
			return "", nil
		},
		send: func(c context.Context, token, user, recipient string) error {
			return nil
		},
	}, "", "")
	require.EqualError(t, err, "refused store", "Store() error should propagate")
}

func TestVerifyToken(t *testing.T) {
	valid, err := VerifyToken(nil, &mockTokenStore{
		verify: func(ctx context.Context, token, uid string) (bool, error) {
			return false, fmt.Errorf("refused verify")
		},
	}, "", "")
	require.False(t, valid)
	require.EqualError(t, err, "refused verify", "Verify() error should propagate")

	valid, err = VerifyToken(nil, &mockTokenStore{
		verify: func(ctx context.Context, token, uid string) (bool, error) {
			return false, nil
		},
	}, "", "")
	require.False(t, valid)
	require.NoError(t, err)

	valid, err = VerifyToken(nil, &mockTokenStore{
		verify: func(ctx context.Context, token, uid string) (bool, error) {
			return true, nil
		},
		delete: func(ctx context.Context, uid string) error {
			return fmt.Errorf("delete failure")
		},
	}, "", "")
	require.True(t, valid)
	require.EqualError(t, err, "delete failure")
}

type mockStrategy struct {
	SimpleStrategy
	generate func(context.Context) (string, error)
	sanitize func(context.Context, string) (string, error)
	send     func(c context.Context, token, user, recipient string) error
}

func (m mockStrategy) TTL(ctx context.Context) time.Duration {
	return m.ttl
}

func (m mockStrategy) Generate(ctx context.Context) (string, error) {
	return m.generate(ctx)
}

func (m mockStrategy) Sanitize(ctx context.Context, t string) (string, error) {
	return m.sanitize(ctx, t)
}

func (m mockStrategy) Send(ctx context.Context, token, user, recipient string) error {
	return m.send(ctx, token, user, recipient)
}

type mockTokenStore struct {
	store  func(ctx context.Context, token, uid string, ttl time.Duration) error
	exists func(ctx context.Context, uid string) (bool, time.Time, error)
	verify func(ctx context.Context, token, uid string) (bool, error)
	delete func(ctx context.Context, uid string) error
}

func (m mockTokenStore) Store(ctx context.Context, token, uid string, ttl time.Duration) error {
	return m.store(ctx, token, uid, ttl)
}

func (m mockTokenStore) Exists(ctx context.Context, uid string) (bool, time.Time, error) {
	return m.exists(ctx, uid)
}

func (m mockTokenStore) Verify(ctx context.Context, token, uid string) (bool, error) {
	return m.verify(ctx, token, uid)
}

func (m mockTokenStore) Delete(ctx context.Context, uid string) error {
	return m.delete(ctx, uid)
}

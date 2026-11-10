package actors

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNotifier(t *testing.T) {
	// Retry quickly, so the tests don't wait for the real delay
	prevDelay := notifierInitialRetryDelay
	notifierInitialRetryDelay = 100 * time.Millisecond
	t.Cleanup(func() {
		notifierInitialRetryDelay = prevDelay
	})

	const userID = "user-notifier"

	t.Run("sends the notification for a pending request", func(t *testing.T) {
		n := newTestNotifier(nil)
		h := newTestNotifierHost(t, n, userID)

		const state = "notify-pending"
		seedTestRequest(t, h, userID, state, time.Now().Add(10*time.Minute))
		err := h.NotifyRequestCreated(t.Context(), userID, state, "https://revaulter.example.com")
		require.NoError(t, err)

		got := n.waitForCalls(t, 1)
		assert.Equal(t, "https://revaulter.example.com", got[0].BaseURL)
		assert.Equal(t, userID, got[0].UserDisplayName)
		assert.Equal(t, "encrypt", got[0].Operation)
		assert.Equal(t, "test-key", got[0].KeyLabel)
		assert.Equal(t, "A256GCM", got[0].Algorithm)
		assert.Equal(t, "127.0.0.1", got[0].RequestorIP)
	})

	t.Run("retries a notification that fails", func(t *testing.T) {
		var attempt int
		n := newTestNotifier(func() error {
			attempt++
			if attempt == 1 {
				return errors.New("simulated failure")
			}
			return nil
		})
		h := newTestNotifierHost(t, n, userID)

		const state = "notify-retry"
		seedTestRequest(t, h, userID, state, time.Now().Add(10*time.Minute))
		err := h.NotifyRequestCreated(t.Context(), userID, state, "https://revaulter.example.com")
		require.NoError(t, err)

		n.waitForCalls(t, 2)
		n.assertNoMoreCalls(t, 2)
	})

	t.Run("gives up after the maximum number of attempts", func(t *testing.T) {
		n := newTestNotifier(func() error {
			return errors.New("simulated failure")
		})
		h := newTestNotifierHost(t, n, userID)

		const state = "notify-give-up"
		seedTestRequest(t, h, userID, state, time.Now().Add(10*time.Minute))
		err := h.NotifyRequestCreated(t.Context(), userID, state, "https://revaulter.example.com")
		require.NoError(t, err)

		n.waitForCalls(t, notifierMaxAttempts)
		n.assertNoMoreCalls(t, notifierMaxAttempts)
	})

	t.Run("skips a request that isn't pending anymore", func(t *testing.T) {
		n := newTestNotifier(nil)
		h := newTestNotifierHost(t, n, userID)

		const state = "notify-canceled"
		seedTestRequest(t, h, userID, state, time.Now().Add(10*time.Minute))
		_, err := h.User(userID).Cancel(t.Context(), state, nil)
		require.NoError(t, err)

		err = h.NotifyRequestCreated(t.Context(), userID, state, "https://revaulter.example.com")
		require.NoError(t, err)
		n.assertNoMoreCalls(t, 0)

		// A request that doesn't exist is skipped too
		err = h.NotifyRequestCreated(t.Context(), userID, "does-not-exist", "https://revaulter.example.com")
		require.NoError(t, err)
		n.assertNoMoreCalls(t, 0)
	})

	t.Run("a retry is skipped when the request is not pending anymore", func(t *testing.T) {
		const state = "notify-canceled-before-retry"
		var h *Host
		n := newTestNotifier(func() error {
			// Cancel the request while the first attempt fails, so the retry finds it's not pending
			_, cErr := h.User(userID).Cancel(context.Background(), state, nil)
			if cErr != nil {
				return cErr
			}
			return errors.New("simulated failure")
		})
		h = newTestNotifierHost(t, n, userID)

		seedTestRequest(t, h, userID, state, time.Now().Add(10*time.Minute))
		err := h.NotifyRequestCreated(t.Context(), userID, state, "https://revaulter.example.com")
		require.NoError(t, err)

		n.waitForCalls(t, 1)
		n.assertNoMoreCalls(t, 1)
	})

	t.Run("no notifier", func(t *testing.T) {
		h := newTestHost(t, newTestDB(t, userID), ":memory:")

		err := h.NotifyRequestCreated(t.Context(), userID, "any-state", "https://revaulter.example.com")
		require.NoError(t, err)
	})
}

// newTestNotifierHost returns a running host that sends notifications with the test notifier
func newTestNotifierHost(t *testing.T, n *testNotifier, userIDs ...string) *Host {
	t.Helper()

	h := newUnstartedTestHostWithOptions(t, NewHostOptions{
		DB:       newTestDB(t, userIDs...),
		Notifier: n.notify,
	}, ":memory:")
	RunTestHost(t, h)

	return h
}

// testNotifier records the notifications it's asked to send
type testNotifier struct {
	lock   sync.Mutex
	calls  []RequestNotification
	result func() error
}

// newTestNotifier returns a test notifier, which returns the result of the function for each notification, if set
func newTestNotifier(result func() error) *testNotifier {
	return &testNotifier{
		result: result,
	}
}

func (n *testNotifier) notify(_ context.Context, rn RequestNotification) error {
	n.lock.Lock()
	n.calls = append(n.calls, rn)
	n.lock.Unlock()

	if n.result != nil {
		return n.result()
	}
	return nil
}

// getCalls returns a copy of the notifications received so far
func (n *testNotifier) getCalls() []RequestNotification {
	n.lock.Lock()
	defer n.lock.Unlock()

	return append([]RequestNotification(nil), n.calls...)
}

// waitForCalls waits until the notifier has received count notifications, and returns them
func (n *testNotifier) waitForCalls(t *testing.T, count int) []RequestNotification {
	t.Helper()

	require.Eventually(t, func() bool {
		return len(n.getCalls()) >= count
	}, 15*time.Second, 50*time.Millisecond, "expected %d notifications", count)

	return n.getCalls()
}

// assertNoMoreCalls waits a little, and asserts the notifier received exactly count notifications
func (n *testNotifier) assertNoMoreCalls(t *testing.T, count int) {
	t.Helper()

	time.Sleep(2 * time.Second)
	assert.Len(t, n.getCalls(), count)
}

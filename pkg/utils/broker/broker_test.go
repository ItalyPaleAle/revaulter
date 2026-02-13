package broker

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestBroker(t *testing.T) {
	broker := NewBroker[int]()

	// Subscribe 3 times
	var (
		subs [3]chan int
		err  error
	)
	subs[0], err = broker.Subscribe()
	require.NoError(t, err)
	subs[1], err = broker.Subscribe()
	require.NoError(t, err)
	subs[2], err = broker.Subscribe()
	require.NoError(t, err)

	// Send a message
	go func() {
		// Publish in a background goroutine
		broker.Publish(42)
	}()
	var count int
	to := time.After(time.Second)
	for count < 3 {
		var n int
		select {
		case n = <-subs[0]:
			// nop
		case n = <-subs[1]:
			// nop
		case n = <-subs[2]:
			// nop
		case <-to:
			t.Fatalf("timed out while waiting for messages; got %d of 3", count)
		}
		require.Equal(t, 42, n)
		count++
	}
	require.Equal(t, 3, count)

	// Remove one sub
	broker.Unsubscribe(subs[2])

	// Ensure the channel is closed
	assertChanClosed(t, subs[2])

	// Send another message
	go func() {
		// Publish in a background goroutine
		broker.Publish(1)
	}()
	to = time.After(time.Second)
	count = 0
	for count < 2 {
		var n int
		select {
		case n = <-subs[0]:
			// nop
		case n = <-subs[1]:
			// nop
		case <-to:
			t.Fatalf("timed out while waiting for messages; got %d of 3", count)
		}
		require.Equal(t, 1, n)
		count++
	}
	require.Equal(t, 2, count)

	// Close the broker
	broker.Shutdown()

	// Assert all subscriptions are closed
	for _, s := range subs {
		assertChanClosed(t, s)
	}

	// Subscribing should fail
	sub, err := broker.Subscribe()
	require.Error(t, err)
	require.ErrorIs(t, err, ErrBrokerStopped)
	require.Nil(t, sub)
}

func assertChanClosed[T any](t *testing.T, ch chan T) {
	t.Helper()
	select {
	case _, ok := <-ch:
		require.False(t, ok)
	default:
		t.Fatal("channel 2 should have been closed")
	}
}

package broker

import (
	"errors"
	"log/slog"
	"sync"
)

var ErrBrokerStopped = errors.New("broker is stopped")

// Broker is a message broker that publishes events to all subscribers
//
// Publishes are non-blocking: if a subscriber's channel buffer is full, the message is dropped for that subscriber rather than blocking the publisher
// Callers are responsible for draining their subscription channels promptly
type Broker[T any] struct {
	lock        sync.RWMutex
	subscribers map[chan T]struct{}
	stopped     bool
	logger      *slog.Logger
}

// NewBroker returns a new Broker object
func NewBroker[T any]() *Broker[T] {
	return &Broker[T]{
		subscribers: map[chan T]struct{}{},
	}
}

// SetLogger sets an optional logger in the object
func (b *Broker[T]) SetLogger(logger *slog.Logger) {
	b.lock.Lock()
	defer b.lock.Unlock()
	b.logger = logger
}

// Subscribe creates a new subscription
func (b *Broker[T]) Subscribe() (chan T, error) {
	b.lock.Lock()
	defer b.lock.Unlock()

	if b.stopped {
		return nil, ErrBrokerStopped
	}

	// Use a small buffer so an in-flight message does not block a caller that briefly lags behind the publisher
	ch := make(chan T, 8)
	b.subscribers[ch] = struct{}{}

	return ch, nil
}

// Unsubscribe removes a subscription
// The channel is closed by this method
func (b *Broker[T]) Unsubscribe(ch chan T) {
	b.lock.Lock()
	defer b.lock.Unlock()

	_, ok := b.subscribers[ch]
	if ok {
		delete(b.subscribers, ch)
		close(ch)
	}
}

// Shutdown forcefully closes all subscriptions
// Then, it marks the broker as shut down
func (b *Broker[T]) Shutdown() {
	b.lock.Lock()
	defer b.lock.Unlock()

	for ch := range b.subscribers {
		delete(b.subscribers, ch)
		close(ch)
	}

	b.stopped = true
}

// Publish sends a message to all subscribers
func (b *Broker[T]) Publish(msg T) {
	// The read lock is held for the entire Publish so Unsubscribe/Shutdown cannot close a subscriber channel concurrently with a send, which would otherwise panic
	// Non-blocking sends keep Publish bounded, so concurrent Unsubscribe/Shutdown callers only wait microseconds to acquire the write lock
	b.lock.RLock()
	defer b.lock.RUnlock()

	if b.stopped {
		return
	}

	for ch := range b.subscribers {
		// The send is non-blocking: if a subscriber's channel buffer is full, the message is dropped for that subscriber and a warning is emitted
		select {
		case ch <- msg:
		default:
			if b.logger != nil {
				b.logger.Warn("broker subscriber channel full; dropping message")
			}
		}
	}
}

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
//
// The send is non-blocking: if a subscriber's channel buffer is full, the message is dropped for that subscriber and a warning is emitted
// Subscribers snapshot is taken under the read lock and the actual sends happen after the lock is released, so a slow subscriber cannot block Unsubscribe/Shutdown.
func (b *Broker[T]) Publish(msg T) {
	b.lock.RLock()
	logger := b.logger

	if b.stopped {
		b.lock.RUnlock()
		return
	}

	subs := make([]chan T, 0, len(b.subscribers))
	for ch := range b.subscribers {
		subs = append(subs, ch)
	}

	b.lock.RUnlock()

	for _, ch := range subs {
		select {
		case ch <- msg:
		default:
			if logger != nil {
				logger.Warn("broker subscriber channel full; dropping message")
			}
		}
	}
}

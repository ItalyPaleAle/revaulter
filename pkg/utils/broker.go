package utils

import (
	"errors"
	"sync"
)

// Broker is a message broker that publishes events to all subscribers
type Broker[T any] struct {
	lock        sync.RWMutex
	subscribers map[chan T]struct{}
	active      bool
}

// NewBroker returns a new Broker object
func NewBroker[T any]() *Broker[T] {
	return &Broker[T]{
		subscribers: map[chan T]struct{}{},
		active:      true,
	}
}

// Subscribe creates a new subscription
func (b *Broker[T]) Subscribe() (chan T, error) {
	b.lock.Lock()
	defer b.lock.Unlock()

	if !b.active {
		return nil, errors.New("broker is inactive")
	}

	ch := make(chan T)
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

	b.active = false
}

// Publish sends a message to all subscribers
func (b *Broker[T]) Publish(msg T) {
	b.lock.RLock()
	defer b.lock.RUnlock()

	for ch := range b.subscribers {
		ch <- msg
	}
}

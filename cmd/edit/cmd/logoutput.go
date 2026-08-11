package cmd

import (
	"bytes"
	"io"
	"sync"
)

// pausableWriter is an io.Writer that can be told to buffer everything written to it, and to write it all out later
// The log is sent through one of these because editors such as nano and vim draw over the whole terminal: a log line written while one of them is running lands in the middle of what the user is editing
type pausableWriter struct {
	out io.Writer

	mu     sync.Mutex
	buf    bytes.Buffer
	paused bool
}

func newPausableWriter(out io.Writer) *pausableWriter {
	return &pausableWriter{out: out}
}

func (w *pausableWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.paused {
		return w.buf.Write(p)
	}

	return w.out.Write(p)
}

// Pause starts buffering everything that is written, until Resume is called
func (w *pausableWriter) Pause() {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.paused = true
}

// Resume writes out everything that was buffered while paused, and returns to writing through
func (w *pausableWriter) Resume() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.paused = false
	if w.buf.Len() == 0 {
		return nil
	}

	_, err := w.out.Write(w.buf.Bytes())
	w.buf.Reset()

	return err
}

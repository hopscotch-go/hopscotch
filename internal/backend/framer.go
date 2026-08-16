package backend

import (
	"encoding/binary"
	"errors"
	"sync"
)

const (
	frameHeader = 4
	maxFrame    = 1 << 20
)

var (
	ErrFrameTooLarge = errors.New("frame exceeds 1 MiB")
	ErrShortFrame    = errors.New("truncated frame")
)

// StreamFramer splits a byte stream into datagrams.
// Each datagram is a 32-bit big-endian length followed by that many bytes.
type StreamFramer struct {
	mu  sync.Mutex
	buf []byte
	err error
}

// EncodeFrame length-prefixes payload for sending on a stream.
func EncodeFrame(payload []byte) ([]byte, error) {
	if len(payload) > maxFrame {
		return nil, ErrFrameTooLarge
	}
	out := make([]byte, frameHeader+len(payload))
	binary.BigEndian.PutUint32(out[:frameHeader], uint32(len(payload)))
	copy(out[frameHeader:], payload)
	return out, nil
}

// Write appends stream bytes and records an error if a frame length is too large.
func (f *StreamFramer) Write(p []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return
	}
	f.buf = append(f.buf, p...)
	if len(f.buf) >= frameHeader {
		n := int(binary.BigEndian.Uint32(f.buf[:frameHeader]))
		if n > maxFrame {
			f.err = ErrFrameTooLarge
		}
	}
}

// Err returns any framing error observed while buffering.
func (f *StreamFramer) Err() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.err
}

// HasFrame reports whether a complete length-prefixed frame is buffered.
func (f *StreamFramer) HasFrame() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.peek()
	return ok
}

// NextFrame consumes and returns the next complete frame from the buffer.
func (f *StreamFramer) NextFrame() ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	n, ok := f.peek()
	if !ok {
		return nil, ErrShortFrame
	}
	payload := append([]byte(nil), f.buf[frameHeader:frameHeader+n]...)
	f.buf = f.buf[frameHeader+n:]
	return payload, nil
}

// peek reports the next complete frame length if one is fully buffered.
func (f *StreamFramer) peek() (int, bool) {
	if f.err != nil || len(f.buf) < frameHeader {
		return 0, false
	}
	n := int(binary.BigEndian.Uint32(f.buf[:frameHeader]))
	if n > maxFrame {
		return 0, false
	}
	return n, len(f.buf) >= frameHeader+n
}

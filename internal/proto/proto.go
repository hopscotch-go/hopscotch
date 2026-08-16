package proto

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
)

const maxMsg = 1 << 20

type Message struct {
	Type     string    `json:"type"`
	RPC      uint64    `json:"rpc,omitempty"`
	Hello    *Hello    `json:"hello,omitempty"`
	Target   string    `json:"target,omitempty"`
	Contacts []Contact `json:"contacts,omitempty"`
	Name     string    `json:"name,omitempty"`
	Origin   string    `json:"origin,omitempty"`
	Path     []string  `json:"path,omitempty"`
	TTL      int       `json:"ttl,omitempty"`
	Hops     int       `json:"hops,omitempty"`
	RTTMs    float64   `json:"rtt_ms,omitempty"`
	Error    string    `json:"error,omitempty"`
}

type Hello struct {
	Listen []string `json:"listen"`
}

type Contact struct {
	ID    string   `json:"id"`
	Addrs []string `json:"addrs,omitempty"`
}

func Write(w io.Writer, m Message) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(b)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

func Read(r io.Reader) (Message, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Message{}, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > maxMsg {
		return Message{}, fmt.Errorf("bad message length %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return Message{}, err
	}
	var m Message
	if err := json.Unmarshal(buf, &m); err != nil {
		return Message{}, err
	}
	return m, nil
}

package proto

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
)

const maxMsg = 1 << 20

type Message struct {
	Type    string     `json:"type"`
	RPC     uint64     `json:"rpc,omitempty"`
	Hello   *Hello     `json:"hello,omitempty"`
	Name    string     `json:"name,omitempty"`
	Origin  string     `json:"origin,omitempty"`
	Path    []string   `json:"path,omitempty"`
	TTL     int        `json:"ttl,omitempty"`
	Hops    int        `json:"hops,omitempty"`
	RTTMs   float64    `json:"rtt_ms,omitempty"`
	Error   string     `json:"error,omitempty"`
	MaxTTL  int        `json:"max_ttl,omitempty"`
	Trace   []TraceHop `json:"trace,omitempty"`
	Reached bool       `json:"reached,omitempty"`
	Routes  []Route    `json:"routes,omitempty"`
}

// Route is one distance-vector advertisement (overlay ULA + hop metric).
type Route struct {
	Dest   string `json:"dest"`
	Metric int    `json:"metric"`
}

// TraceHop is one probe in a control-plane traceroute response.
type TraceHop struct {
	TTL     int     `json:"ttl"`
	Name    string  `json:"name,omitempty"`
	Addr    string  `json:"addr,omitempty"`
	RTTMs   float64 `json:"rtt_ms,omitempty"`
	Timeout bool    `json:"timeout,omitempty"`
	Reply   string  `json:"reply,omitempty"`
}

type Hello struct {
	Listen []string `json:"listen"`
}

// Write marshals m as length-prefixed JSON onto w.
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

// Read consumes one length-prefixed JSON message from r.
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

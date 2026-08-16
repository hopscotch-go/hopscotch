package backend

import (
	"encoding/binary"
	"errors"
	"testing"
)

func TestEncodeFrameRoundTrip(t *testing.T) {
	raw, err := EncodeFrame([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 9 {
		t.Fatalf("len %d want 9", len(raw))
	}
	if binary.BigEndian.Uint32(raw[:4]) != 5 {
		t.Fatalf("length prefix %d", binary.BigEndian.Uint32(raw[:4]))
	}
	var f StreamFramer
	f.Write(raw[:5])
	if f.HasFrame() {
		t.Fatal("incomplete frame should not be ready")
	}
	f.Write(raw[5:])
	got, err := f.NextFrame()
	if err != nil || string(got) != "hello" {
		t.Fatalf("got %q err %v", got, err)
	}
}

func TestEncodeFrameTwo(t *testing.T) {
	a, _ := EncodeFrame([]byte("a"))
	b, _ := EncodeFrame([]byte("bb"))
	var f StreamFramer
	f.Write(append(append([]byte{}, a...), b...))
	ga, err := f.NextFrame()
	if err != nil {
		t.Fatal(err)
	}
	gb, err := f.NextFrame()
	if err != nil {
		t.Fatal(err)
	}
	if string(ga) != "a" || string(gb) != "bb" {
		t.Fatalf("%q %q", ga, gb)
	}
}

func TestEncodeFrameTooLarge(t *testing.T) {
	_, err := EncodeFrame(make([]byte, maxFrame+1))
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("err %v", err)
	}
}

func TestStreamFramerRejectsOversizedHeader(t *testing.T) {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(maxFrame+1))
	var f StreamFramer
	f.Write(hdr[:])
	if !errors.Is(f.Err(), ErrFrameTooLarge) {
		t.Fatalf("err %v", f.Err())
	}
	if f.HasFrame() {
		t.Fatal("oversized header must not look ready")
	}
}

package main

import (
	"bytes"
	"io"
)

// redactor replaces secret values in a stream with "[tok:redacted]". It holds back the last
// len(longest)-1 bytes so a secret split across two writes is still caught.
type redactor struct {
	w       io.Writer
	secrets [][]byte
	keep    int
	buf     []byte
}

var redactedMark = []byte("[tok:redacted]")

func newRedactor(w io.Writer, secrets []string) *redactor {
	r := &redactor{w: w}
	for _, s := range secrets {
		if len(s) >= 4 { // chisle: shorter values would mangle ordinary output
			r.secrets = append(r.secrets, []byte(s))
			r.keep = max(r.keep, len(s)-1)
		}
	}
	return r
}

func (r *redactor) Write(p []byte) (int, error) {
	r.buf = append(r.buf, p...)
	for _, s := range r.secrets {
		r.buf = bytes.ReplaceAll(r.buf, s, redactedMark)
	}
	// flush everything except a tail that could be the start of a secret; flush whole on newline-free streams too
	cut := len(r.buf) - r.keep
	if cut > 0 {
		if _, err := r.w.Write(r.buf[:cut]); err != nil {
			return 0, err
		}
		r.buf = append(r.buf[:0], r.buf[cut:]...)
	}
	return len(p), nil
}

func (r *redactor) Flush() {
	if len(r.buf) > 0 {
		_, _ = r.w.Write(r.buf)
		r.buf = r.buf[:0]
	}
}

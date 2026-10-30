package main

import (
	"bytes"
	"testing"
)

func TestRedactorSplitWrites(t *testing.T) {
	var out bytes.Buffer
	r := newRedactor(&out, []string{"s3cr3t-value"})
	for _, chunk := range []string{"token=s3c", "r3t-va", "lue ok\nagain s3cr3t-value"} {
		r.Write([]byte(chunk))
	}
	r.Flush()
	want := "token=[tok:redacted] ok\nagain [tok:redacted]"
	if out.String() != want {
		t.Fatalf("got %q want %q", out.String(), want)
	}
}

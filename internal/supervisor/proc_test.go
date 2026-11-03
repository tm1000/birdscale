package supervisor

import (
	"bytes"
	"testing"
)

func TestPrefixWriter(t *testing.T) {
	var b bytes.Buffer
	w := prefixWriter{prefix: "netbird", w: &b}
	w.Write([]byte("one\ntwo\n"))
	if got := b.String(); got != "[netbird] one\n[netbird] two\n" {
		t.Errorf("got %q", got)
	}
}

func TestEnvWithout(t *testing.T) {
	got := EnvWithout([]string{"TS_AUTHKEY=s", "TS_AUTHKEY_X=k", "A=b"}, "TS_AUTHKEY")
	if len(got) != 2 || got[0] != "TS_AUTHKEY_X=k" {
		t.Errorf("got %v", got)
	}
}

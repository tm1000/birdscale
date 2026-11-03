package web

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"time"
)

// csrf issues and checks tokens bound to the caller and the time of the page
// render: "<unix>.<hex(hmac(key, subject|unix))>". The key is random per process,
// so tokens die with a restart, and a token only works for the caller it was
// issued to.
type csrf struct {
	key []byte
	ttl time.Duration
	now func() time.Time
}

func newCSRF() *csrf {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		panic("web: no randomness for CSRF key: " + err.Error())
	}
	return &csrf{key: k, ttl: time.Hour, now: time.Now}
}

func (c *csrf) mac(subject string, ts int64) string {
	m := hmac.New(sha256.New, c.key)
	m.Write([]byte(subject))
	m.Write([]byte{0})
	m.Write([]byte(strconv.FormatInt(ts, 10)))
	return hex.EncodeToString(m.Sum(nil))
}

// Issue returns a token for subject, valid for the ttl.
func (c *csrf) Issue(subject string) string {
	ts := c.now().Unix()
	return strconv.FormatInt(ts, 10) + "." + c.mac(subject, ts)
}

// Verify checks a token for subject.
func (c *csrf) Verify(subject, token string) bool {
	tsStr, mac, ok := strings.Cut(token, ".")
	if !ok {
		return false
	}
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return false
	}
	age := c.now().Sub(time.Unix(ts, 0))
	if age < -time.Minute || age > c.ttl {
		return false
	}
	return hmac.Equal([]byte(mac), []byte(c.mac(subject, ts)))
}

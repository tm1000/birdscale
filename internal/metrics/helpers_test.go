package metrics

import (
	"net/http"
	"net/http/httptest"
)

func newRecorder() *httptest.ResponseRecorder { return httptest.NewRecorder() }
func newGet(path string) *http.Request        { return httptest.NewRequest("GET", path, nil) }

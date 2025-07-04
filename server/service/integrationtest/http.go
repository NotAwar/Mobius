package integrationtest

import (
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/notawar/mobius/server/mobius"
	"github.com/notawar/mobius/server/test/httptest"
	"github.com/go-json-experiment/json"
	"github.com/stretchr/testify/require"
)

func (s *BaseSuite) DoJSON(t *testing.T, verb, path string, params interface{}, expectedStatusCode int, v interface{}, queryParams ...string) {
	resp := s.Do(t, verb, path, params, expectedStatusCode, queryParams...)
	err := json.UnmarshalRead(resp.Body, v)
	require.NoError(t, err)
	if e, ok := v.(mobius.Errorer); ok {
		require.NoError(t, e.Error())
	}
}

func (s *BaseSuite) Do(t *testing.T, verb, path string, params interface{}, expectedStatusCode int, queryParams ...string) *http.Response {
	j, err := json.Marshal(params)
	require.NoError(t, err)

	resp := s.DoRaw(t, verb, path, j, expectedStatusCode, queryParams...)

	t.Cleanup(func() {
		resp.Body.Close()
	})
	return resp
}

func (s *BaseSuite) DoRaw(t *testing.T, verb string, path string, rawBytes []byte, expectedStatusCode int, queryParams ...string) *http.Response {
	return s.DoRawWithHeaders(t, verb, path, rawBytes, expectedStatusCode, map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", s.Token),
	}, queryParams...)
}

func (s *BaseSuite) DoRawWithHeaders(
	t *testing.T, verb string, path string, rawBytes []byte, expectedStatusCode int, headers map[string]string, queryParams ...string,
) *http.Response {
	return httptest.DoHTTPReq(t, decodeJSON, verb, rawBytes, s.Server.URL+path, headers, expectedStatusCode, queryParams...)
}

func decodeJSON(r io.Reader, v interface{}) error {
	return json.UnmarshalRead(r, v)
}

package googleoidcmiddleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	googleoidcmiddleware "github.com/mashiike/google-oidc-middleware"
	"github.com/stretchr/testify/require"
)

func TestGoogleODICSession(t *testing.T) {
	key := []byte("passpasspasspass")
	s := &googleoidcmiddleware.Session{
		IDToken:    "hogehoge",
		RedirectTo: "http://localhost:8080",
		S:          "hoge",
	}
	w := httptest.NewRecorder()
	err := s.MarshalCookie(w, "cookie-test", key)
	require.NoError(t, err)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, cookie := range w.Result().Cookies() {
		r.AddCookie(cookie)
	}
	var restore googleoidcmiddleware.Session
	err = restore.UnmarshalCookie(r, "cookie-test", key)
	require.NoError(t, err)
	require.EqualValues(t, *s, restore)
}

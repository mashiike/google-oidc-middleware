package googleoidcmiddleware

import (
	"context"
	"crypto/aes"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"path"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/samber/lo"
	"github.com/thanhpk/randstr"
	"golang.org/x/oauth2"
)

type Config struct {
	ClientID          string
	ClientSecret      string
	SessionEncryptKey []byte
	CookieName        string
	LoginPath         string
	CallbackPath      string
	BaseURL           *url.URL
	Scopes            []string
	Logger
}

type Logger interface {
	Println(v ...any)
}

type handler struct {
	next http.Handler
	cfg  *Config
}

func New(cfg *Config) (func(next http.Handler) http.Handler, error) {
	if cfg.Logger == nil {
		cfg.Logger = log.New(log.Writer(), "google-oidc", log.Flags())
	}
	if cfg.CookieName == "" {
		cfg.CookieName = "google-oidc"
	}
	if cfg.LoginPath == "" {
		cfg.LoginPath = "/oidc/google/login"
	}
	if cfg.LoginPath == "" {
		cfg.LoginPath = "/oidc/google/idpresponse"
	}
	if cfg.Scopes == nil {
		cfg.Scopes = []string{oidc.ScopeOpenID}
	}
	if !lo.Contains(cfg.Scopes, oidc.ScopeOpenID) {
		cfg.Scopes = append(cfg.Scopes, oidc.ScopeOpenID)
	}
	if _, err := aes.NewCipher(cfg.SessionEncryptKey); err != nil {
		return nil, fmt.Errorf("session encrypt key is invalid:%w", err)
	}
	return func(next http.Handler) http.Handler {
		h := &handler{
			cfg:  cfg,
			next: next,
		}
		return h
	}, nil
}

func WrapGoogleOIDC(next http.Handler, cfg *Config) http.Handler {
	m, err := New(cfg)
	if err != nil {
		panic(err)
	}
	return m(next)
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var session Session
	if err := session.UnmarshalCookie(r, h.cfg.CookieName, h.cfg.SessionEncryptKey); err != nil {
		h.cfg.Println("[debug] session restore", err)
	}
	if path.Join(h.cfg.BaseURL.Path, h.cfg.LoginPath) == r.URL.Path {
		h.handleLogin(w, r, &session)
		return
	}
	if path.Join(h.cfg.BaseURL.Path, h.cfg.CallbackPath) == r.URL.Path {
		h.handleCallback(w, r, &session)
	}
	h.handleDefault(w, r, &session)
}

func (h *handler) handleLogin(w http.ResponseWriter, r *http.Request, session *Session) {
	_, cfg, err := h.newOIDCConfig(r.Context())
	if err != nil {
		h.cfg.Println("[error]", err)
		http.Error(w, fmt.Sprintf("%s", err), http.StatusInternalServerError)
		return
	}
	session.RedirectTo = h.cfg.BaseURL.String()
	if returnPath := r.URL.Query().Get("return"); returnPath != "" {
		redirectTo := h.cfg.BaseURL.JoinPath(returnPath)
		session.RedirectTo = redirectTo.String()
	}

	state := randstr.Hex(16)
	session.S = state
	if err := session.MarshalCookie(w, h.cfg.CookieName, h.cfg.SessionEncryptKey); err != nil {
		h.cfg.Println("[error]", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	authURL := cfg.AuthCodeURL(state, oidc.Nonce(randstr.Hex(16)))
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (h *handler) handleCallback(w http.ResponseWriter, r *http.Request, session *Session) {
	ctx := r.Context()
	provider, cfg, err := h.newOIDCConfig(ctx)
	if err != nil {
		h.cfg.Println("[error]", err)
		http.Error(w, fmt.Sprintf("%s", err), http.StatusInternalServerError)
		return
	}
	state := r.URL.Query().Get("state")
	if session.S == "" {
		h.cfg.Println("[error] cookie s empty")
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	expectedState := session.S
	session.S = ""
	redirectTo := h.cfg.BaseURL.String()
	if session.RedirectTo != "" {
		redirectTo = session.RedirectTo
		session.RedirectTo = ""
	}
	h.cfg.Println("[debug] redirectTo", redirectTo)
	if state != expectedState {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	code := r.URL.Query().Get("code")
	oauth2Token, err := cfg.Exchange(ctx, code)
	if err != nil {
		err = fmt.Errorf("failed to exchange token: %w", err)
		h.cfg.Println("[error]", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		h.cfg.Println("[error] missing token")
		http.Error(w, "missing token", http.StatusInternalServerError)
		return
	}
	session.IDToken = rawIDToken
	idTokenClaims, exp, err := h.checkIDToken(ctx, provider, rawIDToken)
	if err != nil {
		h.cfg.Println("[error]", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if exp.IsZero() {
		exp = time.Now().Add(time.Hour)
	}
	if err := session.MarshalCookie(w, h.cfg.CookieName, h.cfg.SessionEncryptKey); err != nil {
		h.cfg.Println("[error]", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	h.cfg.Println("[info] login:", idTokenClaims["sub"], " exp:", exp)
	http.Redirect(w, r, redirectTo, http.StatusFound)
}

func (h *handler) handleDefault(w http.ResponseWriter, r *http.Request, session *Session) {
	ctx := r.Context()
	provider, _, err := h.newOIDCConfig(ctx)
	if err != nil {
		h.cfg.Println("[error]", err)
		http.Error(w, fmt.Sprintf("%s", err), http.StatusInternalServerError)
		return
	}
	loginURL := h.cfg.BaseURL.JoinPath(h.cfg.LoginPath)
	query := &url.Values{
		"return": []string{r.URL.Path},
	}
	loginURL.RawQuery = query.Encode()
	h.cfg.Println("[debug] login url =", loginURL.String())
	if session.IDToken == "" {
		http.Redirect(w, r, loginURL.String(), http.StatusFound)
		return
	}
	idTokenClaims, exp, err := h.checkIDToken(r.Context(), provider, session.IDToken)
	if err != nil {
		http.Redirect(w, r, loginURL.String(), http.StatusFound)
		return
	}
	if time.Until(exp) < 0 {
		h.cfg.Println("[debug] expired", exp, "until", time.Until(exp))
		http.Redirect(w, r, loginURL.String(), http.StatusFound)
		return
	}
	r = r.WithContext(withIDTokenClaims(r.Context(), idTokenClaims))
	h.next.ServeHTTP(w, r)
}

func (h *handler) checkIDToken(ctx context.Context, provider *oidc.Provider, rawIDToken string) (map[string]interface{}, time.Time, error) {
	oidcConfig := &oidc.Config{
		ClientID: h.cfg.ClientID,
	}
	verifier := provider.Verifier(oidcConfig)
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("failed to verify ID Token: : %w", err)
	}
	idTokenClaims := map[string]interface{}{}
	if err := idToken.Claims(&idTokenClaims); err != nil {
		return nil, time.Time{}, err
	}
	var exp time.Time
	if v, ok := idTokenClaims["exp"].(float64); ok {
		exp = time.Unix(int64(v), 0)
	}
	return idTokenClaims, exp, nil
}

func (h *handler) newOIDCConfig(ctx context.Context) (*oidc.Provider, *oauth2.Config, error) {
	u := h.cfg.BaseURL.JoinPath(h.cfg.CallbackPath)
	provider, err := oidc.NewProvider(ctx, "https://accounts.google.com")
	if err != nil {
		return nil, nil, err
	}
	cfg := &oauth2.Config{
		ClientID:     h.cfg.ClientID,
		ClientSecret: h.cfg.ClientSecret,
		Endpoint:     provider.Endpoint(),
		Scopes:       h.cfg.Scopes,
		RedirectURL:  u.String(),
	}
	return provider, cfg, nil
}

# google-oidc-middleware

[![Documentation](https://godoc.org/github.com/mashiike/google-oidc-middleware?status.svg)](https://godoc.org/github.com/mashiike/google-oidc-middleware)
![Latest GitHub tag](https://img.shields.io/github/tag/mashiike/google-oidc-middleware.svg)
![Github Actions test](https://github.com/mashiike/google-oidc-middleware/workflows/Test/badge.svg?branch=main)
[![Go Report Card](https://goreportcard.com/badge/mashiike/google-oidc-middleware)](https://goreportcard.com/report/mashiike/google-oidc-middleware)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/mashiike/google-oidc-middleware/blob/master/LICENSE)

Google OIDC Middleware for golang

## Usage 

sample go code
```go
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"

	googleoidcmiddleware "github.com/mashiike/google-oidc-middleware"
	"github.com/thanhpk/randstr"
)

func main() {
	log.Println("access http://localhost:8080")
	err := http.ListenAndServe("localhost:8080", googleoidcmiddleware.WrapGoogleOIDC(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := googleoidcmiddleware.IDTokenClaims(r.Context())
			if !ok {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			w.WriteHeader(http.StatusOK)
			e := json.NewEncoder(w)
			e.SetEscapeHTML(true)
			e.SetIndent("", "  ")
			e.Encode(claims)
		}),
		(&googleoidcmiddleware.Config{
			ClientID:          os.Getenv("GOOGLE_CLIENT_ID"),
			ClientSecret:      os.Getenv("GOOGLE_CLIENT_SECRET"),
			SessionEncryptKey: randstr.Bytes(32),
			Scopes:            []string{"email"},
		}).WithBaseURL("http://localhost:8080"),
	))
	if err != nil {
		log.Fatalln(err)
	}
}
```

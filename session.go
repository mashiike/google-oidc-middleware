package googleoidcmiddleware

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type Session struct {
	IDToken    string `json:"id_token,omitempty"`
	RedirectTo string `json:"redirect_to,omitempty"`
	S          string `json:"s,omitempty"`
}

func (s *Session) UnmarshalCookie(r *http.Request, cookieName string, encryptKey []byte) error {
	sessionStr, err := r.Cookie(cookieName)
	if err != nil {
		return fmt.Errorf("cookie: %w", err)
	}
	cipherText, err := base64.RawStdEncoding.DecodeString(sessionStr.Value)
	if err != nil {
		return fmt.Errorf("decodeString: %w", err)
	}

	block, err := aes.NewCipher(encryptKey)
	if err != nil {
		return fmt.Errorf("newCipher: %w", err)
	}
	decryptedText := make([]byte, len(cipherText[aes.BlockSize:]))
	decryptStream := cipher.NewCTR(block, cipherText[:aes.BlockSize])
	decryptStream.XORKeyStream(decryptedText, cipherText[aes.BlockSize:])

	if err := json.Unmarshal(decryptedText, s); err != nil {
		return fmt.Errorf("unmarshal: %w", err)
	}
	return nil
}

func (s *Session) MarshalCookie(w http.ResponseWriter, cookieName string, encryptKey []byte, optFns ...func(*http.Cookie)) error {
	plainText, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	block, err := aes.NewCipher(encryptKey)
	if err != nil {
		return fmt.Errorf("newCipher: %w", err)
	}
	cipherText := make([]byte, aes.BlockSize+len(plainText))
	iv := cipherText[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return fmt.Errorf("readFull: %w", err)
	}
	encryptStream := cipher.NewCTR(block, iv)
	encryptStream.XORKeyStream(cipherText[aes.BlockSize:], plainText)

	sessionStr := base64.RawStdEncoding.EncodeToString(cipherText)
	cookie := &http.Cookie{
		MaxAge:   int(24 * time.Hour.Seconds()),
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
	}
	for _, optFn := range optFns {
		optFn(cookie)
	}
	cookie.Name = cookieName
	cookie.Value = sessionStr
	http.SetCookie(w, cookie)
	return nil
}

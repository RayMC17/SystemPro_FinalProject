package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

const (
	// Set a cookie with a name "session_id"
	sessionIDCookieName = "session_id"
	// Set the session duration to 24 hours
	sessionDuration = time.Hour * 24
	// Set the key used to encrypt the session data
	sessionEncryptionKey = "abcdefghijklmnop"
)

// Declare errors
var (
	ErrValueTooLong = errors.New("cookie value too long")
	ErrInvalidValue = errors.New("invalid cookie value")
)

const nonceSize = 12

// SessionData holds the user's session data
type SessionData struct {
	UserID   int
	UserName string
}

// setCookieHandler sets a new session ID cookie
func setCookieHandler(w http.ResponseWriter, r *http.Request) {
	// Create a new session ID
	//sessionID := generateSessionID()

	// Create the session data to be stored in the cookie
	sessionData := SessionData{
		UserID:   123,
		UserName: "Alice",
	}
	

	// Encrypt the session data
	encryptedSessionData, err := encryptSessionData(sessionData)
	if err != nil {
		log.Printf("error encrypting session data: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	// Create the cookie
	cookie := http.Cookie{
		Name:     sessionIDCookieName,
		Value:    encryptedSessionData, // store encrypted session data in cookie value
		Path:     "/",
		Expires:  time.Now().Add(sessionDuration),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}

	// Set the cookie on the response
	http.SetCookie(w, &cookie)

	w.Write([]byte("the cookie has been set!"))
}

// getCookieHandler reads the session ID cookie and retrieves the session data
func getCookieHandler(w http.ResponseWriter, r *http.Request) {
	// Read the session ID cookie
	cookie, err := r.Cookie(sessionIDCookieName)
	if err != nil {
		switch {
		case errors.Is(err, http.ErrNoCookie):
			http.Error(w, "a cookie was not found", http.StatusBadRequest)
		default:
			log.Printf("error reading cookie: %v", err)
			http.Error(w, "server error", http.StatusInternalServerError)
		}
		return
	}

	// Decrypt the session data
	cookieValue := []byte(cookie.Value)
	sessionData, err := decryptSessionData(cookieValue)
	if err != nil {
		log.Printf("error decrypting session data: %v", err)
		http.Error(w, "invalid cookie value", http.StatusBadRequest)
		return
	}

	// Use the session data
	fmt.Fprintf(w, "User ID: %d\n", sessionData.UserID)
	fmt.Fprintf(w, "User Name: %s\n", sessionData.UserName)
}

// encryptSessionData encrypts the session data using AES-GCM encryption
func encryptSessionData(sessionData SessionData) (string, error) {
	block, err := aes.NewCipher([]byte(sessionEncryptionKey))
	if err != nil {
		return "", fmt.Errorf("error creating cipher block: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("error creating GCM cipher: %v", err)
	}

	// Generate a random nonce
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader,
		nonce); err != nil {
		return "", fmt.Errorf("error generating nonce: %v", err)
	}

	// Convert the session data to a JSON string
	sessionDataJSON, err := json.Marshal(sessionData)
	if err != nil {
		return "", fmt.Errorf("error marshaling session data to JSON: %v", err)
	}

	// Encrypt the session data using GCM
	ciphertext := gcm.Seal(nil, nonce, sessionDataJSON, nil)

	// Combine the nonce and ciphertext into a single string
	encryptedData := base64.StdEncoding.EncodeToString(nonce) + "." + base64.StdEncoding.EncodeToString(ciphertext)

	return encryptedData, nil
}

// decryptSessionData decrypts the session data using AES-GCM decryption
func DecryptSessionData(encodedEncryptedSessionData []byte) (SessionData, error) {
	encryptedSessionDataWithNonce, err := base64.URLEncoding.DecodeString(string(encodedEncryptedSessionData))
	if err != nil {
		return SessionData{}, fmt.Errorf("error decoding base64 string: %v", err)
	}

	if len(encryptedSessionDataWithNonce) < nonceSize {
		return SessionData{}, fmt.Errorf("invalid encrypted session data: %v", ErrInvalidValue)
	}

	// Split the nonce and encrypted session data
	nonce := encryptedSessionDataWithNonce[:nonceSize]
	encryptedSessionData := encryptedSessionDataWithNonce[nonceSize:]

	block, err := aes.NewCipher([]byte(sessionEncryptionKey))
	if err != nil {
		return SessionData{}, fmt.Errorf("error creating cipher block: %v", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return SessionData{}, fmt.Errorf("error creating GCM cipher: %v", err)
	}

	// Decrypt the session data using GCM
	jsonSessionData, err := aesGCM.Open(nil, nonce, encryptedSessionData, nil)
	if err != nil {
		return SessionData{}, fmt.Errorf("error decrypting session data: %v", err)
	}

	// Convert JSON session data to struct
	var sessionData SessionData
	if err := json.Unmarshal(jsonSessionData, &sessionData); err != nil {
		return SessionData{}, fmt.Errorf("error unmarshaling JSON to session data: %v", err)
	}

	return sessionData, nil
}

// generateSessionID generates a new session ID
func generateSessionID() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		panic(fmt.Errorf("error generating random bytes: %v", err))
	}
	return base64.URLEncoding.EncodeToString(b)
}

// Write sets the given cookie and encrypted session data in the http.ResponseWriter
func Write(w http.ResponseWriter, cookie *http.Cookie, encryptedSessionData string) error {
	if len(cookie.String()+encryptedSessionData) > 4096 {
		return ErrValueTooLong
	}
	cookie.Value = encryptedSessionData
	http.SetCookie(w, cookie)

	return nil
}

// encryptSessionData encrypts the session data using AES-GCM encryption
func EncryptSessionData(sessionData SessionData) (string, error) {
	// Convert session data to JSON
	jsonData, err := json.Marshal(sessionData)
	if err != nil {
		return "", fmt.Errorf("error marshaling session data: %v", err)
	}

	// Generate a new nonce
	nonce := make([]byte, nonceSize)
	_, err = rand.Read(nonce)
	if err != nil {
		return "", fmt.Errorf("error generating nonce: %v", err)
	}

	// Create a new cipher block using the AES algorithm
	block, err := aes.NewCipher([]byte(sessionEncryptionKey))
	if err != nil {
		return "", fmt.Errorf("error creating cipher block: %v", err)
	}

	// Create a new GCM cipher using the block and the nonce
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("error creating GCM cipher: %v", err)
	}

	// Encrypt the session data using the GCM cipher and the nonce
	ciphertext := aesgcm.Seal(nil, nonce, jsonData, nil)

	// Append the nonce to the ciphertext
	encryptedSessionData := append(nonce, ciphertext...)

	// Return the encrypted session data as a base64-encoded string
	return base64.URLEncoding.EncodeToString(encryptedSessionData), nil
}

// decryptSessionData decrypts the session data using AES-GCM decryption
func decryptSessionData(encodedEncryptedSessionData []byte) (SessionData, error) {
	encryptedSessionDataWithNonce, err := base64.URLEncoding.DecodeString(string(encodedEncryptedSessionData))
	if err != nil {
		return SessionData{}, fmt.Errorf("error decoding base64 string: %v", err)
	}

	if len(encryptedSessionDataWithNonce) < nonceSize {
		return SessionData{}, fmt.Errorf("invalid encrypted session data: %v", ErrInvalidValue)
	}

	// Split the nonce and encrypted session data
	nonce := encryptedSessionDataWithNonce[:nonceSize]
	encryptedSessionData := encryptedSessionDataWithNonce[nonceSize:]

	// Create a new cipher block using the AES algorithm
	block, err := aes.NewCipher([]byte(sessionEncryptionKey))
	if err != nil {
		return SessionData{}, fmt.Errorf("error creating cipher block: %v", err)
	}

	// Create a new GCM cipher using the block and the nonce
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return SessionData{}, fmt.Errorf("error creating GCM cipher: %v", err)
	}

	// Decrypt the session data using the GCM cipher and the nonce
	jsonSessionData, err := aesgcm.Open(nil, nonce, encryptedSessionData, nil)
	if err != nil {
		return SessionData{}, fmt.Errorf("error decrypting session data: %v", err)
	}

	// Unmarshal the JSON-encoded session data into a SessionData struct
	var sessionData SessionData
	if err := json.Unmarshal(jsonSessionData, &sessionData); err != nil {
		return SessionData{}, fmt.Errorf("error unmarshaling session data: %v", err)
	}

	return sessionData, nil
}
// Define the function to handle requests to the root URL ("/").
func homeHandler(w http.ResponseWriter, r *http.Request) {
	// Send a plain text welcome message to the client.
	fmt.Fprintf(w, "Welcome to our homepage!")
}

func main() {
	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/set-cookie", setCookieHandler)
	http.HandleFunc("/get-cookie", getCookieHandler)
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}
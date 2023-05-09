package cookies

import (
    "encoding/base64"
    "errors"
    "net/http"
	
)
// ErrValueTooLong is an error returned by the Write function when the cookie value is longer than 4096 bytes.

var ErrValueTooLong = errors.New("cookie value too long")
// ErrInvalidValue is an error returned by the Read function when the cookie
// value is not valid base64-encoded data.
var ErrInvalidValue = errors.New("invalid cookie value")

// Write writes a cookie to the given response writer.
func Write(w http.ResponseWriter, cookie http.Cookie) error {
    // Encode the cookie value using base64.
    cookie.Value = base64.URLEncoding.EncodeToString([]byte(cookie.Value))

    // Check the total length of the cookie contents. Return the ErrValueTooLong
    // error if it's more than 4096 bytes.
    if len(cookie.String()) > 4096 {
        return ErrValueTooLong
    }

    // Write the cookie as normal.
    http.SetCookie(w, &cookie)

    return nil
}

// Read reads a cookie from the given request, and returns its decoded value.
func Read(r *http.Request, name string) (string, error) {
    // Read the cookie as normal.
    cookie, err := r.Cookie(name)
    if err != nil {
        return "", err
    }

    // Decode the base64-encoded cookie value. 
    value, err := base64.URLEncoding.DecodeString(cookie.Value)
    if err != nil {
        return "", ErrInvalidValue
    }

    // Return the decoded cookie value.
    return string(value), nil
}
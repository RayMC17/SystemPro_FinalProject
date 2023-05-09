// Encoding special characters and maximum length
package main

// Sir one thing we forgot to mention in our code is that when you do /get in the browser you will
//see the string "Me gusta pegarle a la piñata! ¿Y tú?" in the prevoius video witht he basic cookie
// if you plce this string to output it will not show it correctly as in this code go has this thing that
//it will ignore the special chanracters and when it is output these character are blocked so the letter
// n with the ~ this character will not be shown and the u with the ` tilde will not be shown on the bowser aswell.
//NOTE: sir about the 1st code with the basic cookie I build up on it for this code here so I don't have that one in
//my reposotory.

import (
	"errors"
	"fmt"
	"log"
	"net/http"

	"github.com/RayMC17/finalProject/internal/cookies" //Import the internal/cookies package.
)

// Define the function to handle setting a cookie when requested.
func setCookieHandler(w http.ResponseWriter, r *http.Request) {
	// Initialize the cookie with the desired values.
	cookie := http.Cookie{
		Name:     "CookieMonster",                // Set the name of the cookie.
		Value:    "Me gusta pegarle a la piñata! ¿Y tú?", // Set the value of the cookie.
		Path:     "/",                           // Set the path that the cookie applies to.
		MaxAge:   3600,                          // Set the maximum age of the cookie (in seconds).
		HttpOnly: true,                          // Set the HttpOnly flag to prevent client-side script access to the cookie.
		Secure:   true,                          // Set the Secure flag to ensure that the cookie is only sent over HTTPS.
		SameSite: http.SameSiteLaxMode,          // Set the SameSite flag to limit cross-site requests.
	}

	// Write the cookie to the response writer. If an error occurs, log the error and send a 500 Internal Server Error response.
	err := cookies.Write(w, cookie)
	if err != nil {
		log.Println(err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	// If the cookie was successfully written, send a success message back to the client.
	w.Write([]byte("cookie set!"))
}

// Define the function to handle getting a cookie when requested.
func getCookieHandler(w http.ResponseWriter, r *http.Request) {
	// Use the Read() function from the cookies package to retrieve the value of the cookie.
	// If an error occurs, handle it appropriately based on the type of error that occurred.
	value, err := cookies.Read(r, "CookieMonster")
	if err != nil {
		switch {
		case errors.Is(err, http.ErrNoCookie):
			// If the cookie was not found, send a 400 Bad Request response indicating that the cookie was not found.
			http.Error(w, "cookie not found", http.StatusBadRequest)
		case errors.Is(err, cookies.ErrInvalidValue):
			// If the cookie value is invalid, send a 400 Bad Request response indicating that the cookie value is invalid.
			http.Error(w, "invalid cookie", http.StatusBadRequest)
		default:
			// If an unexpected error occurred, log the error and send a 500 Internal Server Error response.
			log.Println(err)
			http.Error(w, "server error", http.StatusInternalServerError)
		}
		return
	}

	// If the cookie value was successfully retrieved, send it back to the client.
	w.Write([]byte(value))
}

// Define the function to handle requests to the root URL ("/").
func homeHandler(w http.ResponseWriter, r *http.Request) {
	// Send a plain text welcome message to the client.
	fmt.Fprintf(w, "Welcome to our homepage!")
}

func main() {
	// Create a new ServeMux to handle incoming HTTP requests.
	mux := http.NewServeMux()

	// Register the homeHandler() function to handle requests to the root URL ("/").
	mux.HandleFunc("/", homeHandler)

	// Register the setCookieHandler() function to handle requests to the "/set" URL.
	mux.HandleFunc("/set", setCookieHandler)

	// Register the getCookieHandler() function to handle requests to the "/get" URL.
	mux.HandleFunc("/get", getCookieHandler)

	// Start the HTTP server listening on port 8888.
	log.Print("Listening...")
	err := http.ListenAndServe(":8888", mux)
	if err != nil {
		log.Fatal(err)
	}

}

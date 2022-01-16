// Package render implements a custom JSON renderer for chi. It's similar to the one from the github.com/go-chi/render
// package, but allows us to pass the status code and the content type to the renderer.
package render

import (
	"bytes"
	"encoding/json"
	"net/http"
)

// JSON marshals 'v' to JSON, automatically escaping HTML and setting the HTTP status and Content-Type. If the
// Content-Type is an empty string we set it to "application/json; charset=utf-8".
func JSON(w http.ResponseWriter, r *http.Request, status int, contentType string, v interface{}) {
	buf := &bytes.Buffer{}
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(true)
	if err := enc.Encode(v); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if contentType == "" {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
	} else {
		w.Header().Set("Content-Type", contentType)
	}

	w.WriteHeader(status)
	w.Write(buf.Bytes())
}

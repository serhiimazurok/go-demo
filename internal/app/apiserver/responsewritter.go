package apiserver

import "net/http"

type responseWritter struct {
	http.ResponseWriter
	code int
}

func (w *responseWritter) WriteHeader(statusCode int) {
	w.code = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

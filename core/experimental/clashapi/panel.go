package clashapi

import (
	_ "embed"
	"net/http"
)

//go:embed panel.html
var panelHTML []byte

func panelHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		w.Write(panelHTML)
	}
}

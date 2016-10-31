package app

import (
	"github.com/nirasan/gae-unity-jwt-sample-server/handler"
	"net/http"
)

func init() {
	http.Handle("/", handler.NewHandler())
}

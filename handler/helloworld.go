package handler

import (
	"net/http"

	"github.com/dgrijalva/jwt-go"
	. "github.com/nirasan/gae-unity-jwt-sample-server/classes"
)

// 誰でも閲覧可能なコンテンツ
func HelloWorldHandler(w http.ResponseWriter, r *http.Request) {
	EncodeJson(w, HelloWorldHandlerResponse{Success: true, Message: "Hello World"})
}

// 認証済みのユーザーのみ閲覧可能なコンテンツ
func AuthorizedHelloWorldHandler(w http.ResponseWriter, r *http.Request) {

	// Authorization ヘッダーに入っているトークンを検証する
	token, e := Authorization(w, r)

	if e != nil {
		EncodeJson(w, HelloWorldHandlerResponse{Success: false})
		return
	}

	// トークンからユーザー名を取得してレスポンスに記載する
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		EncodeJson(w, HelloWorldHandlerResponse{Success: true, Message: "Hello " + claims["sub"].(string)})
	}
}

package handler

import (
	"net/http"
	"github.com/gorilla/mux"
)

// App Engine のメイン実行ファイルの init 関数から利用されるルーティング設定を返却する関数
func NewHandler() http.Handler {
	// ルータの初期化
	r := mux.NewRouter()
	// ユーザー登録
	r.HandleFunc("/registration", RegistrationHandler)
	// ユーザー認証
	r.HandleFunc("/authentication", AuthenticationHandler)
	// 認証済みユーザーのみ閲覧可能なコンテンツ
	r.HandleFunc("/authorized_hello", AuthorizedHelloWorldHandler)
	// だれでも閲覧可能なコンテンツ
	r.HandleFunc("/hello", HelloWorldHandler)
	// ルータの返却
	return r
}


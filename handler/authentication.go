package handler

import (
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	. "github.com/nirasan/gae-unity-jwt-sample-server/classes"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/appengine"
	"google.golang.org/appengine/datastore"
)

// ユーザー認証処理
// ユーザー名とパスワードを受け取ってユーザーが存在したら JWT のトークンを返す
func AuthenticationHandler(w http.ResponseWriter, r *http.Request) {

	// リクエスト型のデコード
	var req AuthenticationHandlerRequest
	DecodeJson(r, &req)

	// ユーザーが存在するかどうか確認
	ctx := appengine.NewContext(r)
	key := datastore.NewKey(ctx, "UserAuthentication", req.Username, 0, nil)
	var userAuthentication UserAuthentication
	if err := datastore.Get(ctx, key, &userAuthentication); err != nil {
		EncodeJson(w, AuthenticationHandlerResponse{Success: false})
		return
	}
	// パスワードの検証
	if err := bcrypt.CompareHashAndPassword([]byte(userAuthentication.Password), []byte(req.Password)); err != nil {
		EncodeJson(w, AuthenticationHandlerResponse{Success: false})
		return
	}

	// アクセストークンの作成
	accessToken, e := CreateToken(jwt.MapClaims{
		"sub": req.Username,
		"exp": time.Now().Add(time.Hour * 1).Unix(),
	})
	if e != nil {
		panic(e)
	}

	// 更新トークンの作成
	refreshToken, e := CreateToken(jwt.MapClaims{
		"sub": req.Username,
		"exp": time.Now().Add(time.Hour * 24).Unix(),
	})
	if e != nil {
		panic(e)
	}

	// ヘッダーでトークンを返却
	w.Header().Set("Set-AccessToken", accessToken)
	w.Header().Set("Set-RefreshToken", refreshToken)
	EncodeJson(w, AuthenticationHandlerResponse{Success: true})
}

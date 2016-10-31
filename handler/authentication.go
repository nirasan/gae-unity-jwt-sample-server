package handler

import (
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/nirasan/gae-unity-jwt-sample-server/bindata"
	. "github.com/nirasan/gae-unity-jwt-sample-server/classes"
	"google.golang.org/appengine"
	"google.golang.org/appengine/datastore"
	"golang.org/x/crypto/bcrypt"
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

	// 秘密鍵を go-bindata で固めたデータから取得
	pem, e := bindata.Asset("assets/ec256-key-pri.pem")
	if e != nil {
		panic(e.Error())
	}
	// 署名アルゴリズムの作成
	method := jwt.GetSigningMethod("ES256")
	// トークンの作成
	token := jwt.NewWithClaims(method, jwt.MapClaims{
		"sub": req.Username,
		"exp": time.Now().Add(time.Hour * 1).Unix(),
	})
	// 秘密鍵のパース
	privateKey, e := jwt.ParseECPrivateKeyFromPEM(pem)
	if e != nil {
		panic(e.Error())
	}
	// トークンの署名
	signedToken, e := token.SignedString(privateKey)
	if e != nil {
		panic(e.Error())
	}

	// JSON でトークンを返却
	EncodeJson(w, AuthenticationHandlerResponse{Success: true, Token: signedToken})
}

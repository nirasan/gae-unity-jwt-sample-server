package handler

import (
	"encoding/json"
	"net/http"

	"errors"
	"github.com/dgrijalva/jwt-go"
	"github.com/nirasan/gae-unity-jwt-sample-server/bindata"
	"strings"
)

// トークンの認可
func Authorization(r *http.Request) (*jwt.Token, error) {

	// Authorization ヘッダーの取得
	header := r.Header.Get("Authorization")
	if header == "" {
		return nil, errors.New("Invalid authorization hader")
	}

	// Authorization ヘッダーの解析
	// "Authorization: Bearer <TOKEN>" の形式を想定している
	parts := strings.SplitN(header, " ", 2)
	if !(len(parts) == 2 && parts[0] == "Bearer") {
		return nil, errors.New("Invalid authorization hader")
	}

	// トークンの展開
	// ハッシュ化されているトークンを *jwt.Token 型に変換する
	token, e := jwt.Parse(parts[1], func(t *jwt.Token) (interface{}, error) {

		// 署名アルゴリズムの検証
		method := jwt.GetSigningMethod("ES256")
		if method != t.Method {
			return nil, errors.New("Invalid signing method")
		}

		// go-bindata で固められた公開鍵を読み込む
		pem, e := bindata.Asset("assets/ec256-key-pub.pem")
		if e != nil {
			return nil, e
		}

		// 公開鍵のパース
		key, e := jwt.ParseECPublicKeyFromPEM(pem)
		if e != nil {
			return nil, e
		}

		// 公開鍵を復号化に使うデータとして返却
		return key, nil
	})
	if e != nil {
		return nil, errors.New(e.Error())
	}

	// トークンの検証
	if _, ok := token.Claims.(jwt.MapClaims); !ok || !token.Valid {
		return nil, errors.New("Invalid token")
	}

	return token, nil
}

// POST された JSON データをデコードする
func DecodeJson(r *http.Request, data interface{}) {
	decoder := json.NewDecoder(r.Body)
	defer r.Body.Close()
	if e := decoder.Decode(data); e != nil {
		panic(e.Error())
	}
}

// JSON データでレスポンスを行う
func EncodeJson(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}
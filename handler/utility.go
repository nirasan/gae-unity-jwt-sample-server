package handler

import (
	"encoding/json"
	"net/http"

	"crypto/ecdsa"
	"errors"
	"github.com/dgrijalva/jwt-go"
	"github.com/nirasan/gae-unity-jwt-sample-server/bindata"
	"strings"
)

func CreateToken(claims jwt.Claims) (string, error) {

	// 署名アルゴリズムの作成
	method := jwt.GetSigningMethod("ES256")

	// トークンの作成
	token := jwt.NewWithClaims(method, claims)

	// 秘密鍵の取得
	privateKey, e := getPrivateKey()
	if e != nil {
		return "", e
	}

	// トークンの署名
	signedToken, e := token.SignedString(privateKey)
	if e != nil {
		return "", e
	}

	return signedToken, nil
}

var cachedPrivateKey *ecdsa.PrivateKey

func getPrivateKey() (*ecdsa.PrivateKey, error) {

	if cachedPrivateKey != nil {
		return cachedPrivateKey, nil
	}

	// 秘密鍵を go-bindata で固めたデータから取得
	pem, e := bindata.Asset("assets/ec256-key-pri.pem")
	if e != nil {
		return nil, e
	}
	// 秘密鍵のパース
	key, e := jwt.ParseECPrivateKeyFromPEM(pem)
	if e != nil {
		return nil, e
	}

	cachedPrivateKey = key
	return cachedPrivateKey, nil
}

var cachedPublicKey *ecdsa.PublicKey

func getPublicKey() (*ecdsa.PublicKey, error) {

	if cachedPublicKey != nil {
		return cachedPublicKey, nil
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

	cachedPublicKey = key
	return cachedPublicKey, nil
}

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

		// 公開鍵の取得
		key, e := getPublicKey()
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

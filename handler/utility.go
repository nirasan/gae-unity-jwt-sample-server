package handler

import (
	"encoding/json"
	"net/http"

	"crypto/ecdsa"
	"errors"
	"github.com/dgrijalva/jwt-go"
	"github.com/nirasan/gae-unity-jwt-sample-server/bindata"
	"strings"
	"time"
)

var (
	cachedPrivateKey *ecdsa.PrivateKey
	cachedPublicKey *ecdsa.PublicKey
)

func CreateToken(claims jwt.Claims) (*jwt.Token, string, error) {

	// 署名アルゴリズムの作成
	method := jwt.GetSigningMethod("ES256")

	// トークンの作成
	token := jwt.NewWithClaims(method, claims)

	// 秘密鍵の取得
	privateKey, e := getPrivateKey()
	if e != nil {
		return nil, "", e
	}

	// トークンの署名
	signedToken, e := token.SignedString(privateKey)
	if e != nil {
		return nil, "", e
	}

	return token, signedToken, nil
}

// トークンの認可
func Authorization(w http.ResponseWriter, r *http.Request) (*jwt.Token, error) {

	// アクセストークンの取得
	token, e := getAccessToken(r)

	// トークンが正常な場合
	if e == nil {
		return token, nil
	}

	// 有効期限切れの場合
	if ve, ok := e.(*jwt.ValidationError); ok && (ve.Errors & jwt.ValidationErrorExpired) != 0 {

		refreshToken, e2 := getRefreshToken(r)

		if e2 != nil {
			return nil, e2
		}

		claims, ok := refreshToken.Claims.(jwt.MapClaims)
		if !ok {
			return nil, errors.New("invalid refresh token")
		}

		// アクセストークンの更新
		newToken, accessToken, e := CreateToken(jwt.MapClaims{
			"sub": claims["sub"].(string),
			"exp": time.Now().Add(time.Hour * 1).Unix(),
		})
		if e != nil {
			return nil, errors.New("failed to new access token")
		}
		newToken.Valid = true

		// 更新トークンの更新
		_, newRefreshToken, e := CreateToken(jwt.MapClaims{
			"sub": claims["sub"].(string),
			"exp": time.Now().Add(time.Hour * 24).Unix(),
		})
		if e != nil {
			return nil, errors.New("failed to new refresh token")
		}

		// ヘッダーでトークンを返却
		w.Header().Set("Set-AccessToken", accessToken)
		w.Header().Set("Set-RefreshToken", newRefreshToken)

		return newToken, nil
	}

	return nil, e
}

func getAccessToken(r *http.Request) (*jwt.Token, error) {
	return getToken(r, "access")
}

func getRefreshToken(r *http.Request) (*jwt.Token, error) {
	return getToken(r, "refresh")
}

func getToken(r *http.Request, key string) (*jwt.Token, error) {

	// Authorization ヘッダーの取得
	header := r.Header.Get("Authorization")
	if header == "" {
		return nil, errors.New("Invalid authorization hader")
	}

	// Authorization ヘッダーの解析
	// 'Authorization: token access="ACCESS_TOKEN" refresh="REFRESH_TOKEN"' の形式を想定している
	parts := strings.Split(header, " ")
	if parts[0] != "token" {
		return nil, errors.New("Invalid authorization hader")
	}
	for i := 1; i < len(parts); i++ {
		param := strings.Split(parts[i], "=")
		if len(param) == 2 && param[0] == key {
			val := strings.Trim(param[1], `"`)
			token, e := jwt.Parse(val, getPublicKeyData)
			if e != nil {
				return nil, e
			}
			return token, nil
		}
	}

	return nil, errors.New("token not found")
}

func getPublicKeyData(t *jwt.Token) (interface{}, error) {
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
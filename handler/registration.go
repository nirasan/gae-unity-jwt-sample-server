package handler

import (
	"net/http"

	"errors"
	. "github.com/nirasan/gae-unity-jwt-sample-server/classes"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/net/context"
	"google.golang.org/appengine"
	"google.golang.org/appengine/datastore"
)

// ユーザー登録処理
// ユーザー名とパスワードを受け取って Datastore に登録する
func RegistrationHandler(w http.ResponseWriter, r *http.Request) {

	// POST のペイロードで JSON を受け取ってリクエスト型にデコードする
	var req RegistrationHandlerRequest
	DecodeJson(r, &req)

	// ユーザー情報の登録準備
	ctx := appengine.NewContext(r)
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		panic(err.Error())
	}
	ua := UserAuthentication{Username: req.Username, Password: string(hashedPassword)}

	// Datastore へユーザー情報を登録
	err = datastore.RunInTransaction(ctx, func(ctx context.Context) error {
		key := datastore.NewKey(ctx, "UserAuthentication", req.Username, 0, nil)
		var userAuthentication UserAuthentication
		if err := datastore.Get(ctx, key, &userAuthentication); err != datastore.ErrNoSuchEntity {
			return errors.New("user already exist")
		}
		if _, err := datastore.Put(ctx, key, &ua); err == nil {
			return nil
		} else {
			return err
		}
	}, nil)

	if err == nil {
		EncodeJson(w, RegistrationHandlerResponse{Success: true})
	} else {
		EncodeJson(w, RegistrationHandlerResponse{Success: false})
	}
}

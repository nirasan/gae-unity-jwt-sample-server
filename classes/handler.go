package classes

// registration のリクエスト型
type RegistrationHandlerRequest struct {
	Username string
	Password string
}

// registration のレスポンス型
type RegistrationHandlerResponse struct {
	Success bool
}

// authentication のリクエスト型
type AuthenticationHandlerRequest struct {
	Username string
	Password string
}

// authentication のレスポンス型
type AuthenticationHandlerResponse struct {
	Success bool
	Token   string
}

// コンテンツ共通のレスポンス型
type HelloWorldHandlerResponse struct {
	Success bool
	Message string
}

package oauth

import "net/http"

const (
	HeaderXPublic = "X-Public"
)

type oauthClient struct{}

type oauthInterface interface {
}

func IsPublic(request *http.Request) bool {
	if request == nil {
		return true
	}
	return request.Header.Get(HeaderXPublic) == "true"
}

func AuthenticateRequest(request *http.Request) {
	if request==nil{
		return
	}

}

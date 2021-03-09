package oauth

import (
	"encoding/json"
	"fmt"
	"github.com/Mixilino/oauth_microservice-go/oauth/errs"
	"github.com/mercadolibre/golang-restclient/rest"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	headerXPublic    = "X-Public"
	headerXClientId  = "X-Client-Id"
	headerXCallerrId = "X-Caller-Id"
	paramAccessToken = "access_token"
)

var (
	oauthRestClient = rest.RequestBuilder{
		BaseURL: "http://localhost:8081",
		Timeout: 200 * time.Millisecond,
	}
)

type accessToken struct {
	Id       string `json:"id"`
	UserId   int64  `json:"user_id"`
	ClientId int64  `json:"client_id"`
}

type oauthClient struct{}

type oauthInterface interface {
}

func GetCallerId(r *http.Request) int64 {
	if r == nil {
		return 0
	}
	callerId, err := strconv.ParseInt(r.Header.Get(headerXCallerrId), 10, 64)
	if err != nil {
		return 0
	}
	return callerId
}
func GetClientId(r *http.Request) int64 {
	if r == nil {
		return 0
	}
	callerId, err := strconv.ParseInt(r.Header.Get(headerXClientId), 10, 64)
	if err != nil {
		return 0
	}
	return callerId
}

func IsPublic(request *http.Request) bool {
	if request == nil {
		return true
	}
	return request.Header.Get(headerXPublic) == "true"
}

func AuthenticateRequest(request *http.Request) *errs.RestErr {
	if request == nil {
		return nil
	}
	cleanRequest(request)

	accessTokenId := strings.TrimSpace(request.URL.Query().Get(paramAccessToken))
	if accessTokenId == "" {
		return nil
	}
	at, err := getAccessToken(accessTokenId)
	if err != nil {
		return err
	}
	request.Header.Add(headerXCallerrId, fmt.Sprintf("%v", at.UserId))
	request.Header.Add(headerXClientId, fmt.Sprintf("%v", at.ClientId))
	return nil
}

func cleanRequest(request *http.Request) {
	if request == nil {
		return
	}
	request.Header.Del(headerXCallerrId)
	request.Header.Del(headerXClientId)
}

func getAccessToken(accessTokenId string) (*accessToken, *errs.RestErr) {
	response := oauthRestClient.Get(fmt.Sprintf("/oauth/access_token/%s", accessTokenId))
	if response == nil || response.Response == nil {
		return nil, errs.NewInternalServerError()
	}
	if response.StatusCode > 299 {
		var restErr errs.RestErr
		err := json.Unmarshal(response.Bytes(), &restErr)
		if err != nil {
			log.Println("Invalid error response")
			return nil, errs.NewInternalServerError()
		}
		return nil, &restErr
	}
	var at accessToken
	if err := json.Unmarshal(response.Bytes(), &at); err != nil {
		log.Println("Error trying to unmarshal accesstoken")
		return nil, errs.NewInternalServerError()
	}
	return &at, nil
}

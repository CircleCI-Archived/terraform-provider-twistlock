package client

import (
	"crypto/tls"
	"net/http"
)

type Client struct {
	username string
	password string
	baseURL  string
	http     http.Client
}

func NewClient(username, password, baseURL string, skipTLSVerify bool) Client {
	return Client{
		username: username,
		password: password,
		baseURL:  baseURL,
		http: http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: skipTLSVerify,
				},
			}},
	}
}

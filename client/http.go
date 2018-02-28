package client

import (
	"net/http"
)

type Client struct {
	username string
	password string
	baseURL  string
	http     http.Client
}

func NewClient(username, password, baseURL string) Client {
	return Client{
		username: username,
		password: password,
		baseURL:  baseURL,
		http:     http.Client{},
	}
}

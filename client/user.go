package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/circleci/terraform-provider-twistlock/model"
)

var userPath = "/users"

func userById(id string) func(*model.User) bool {
	return func(u *model.User) bool {
		return u.ID == id
	}
}

func userByName(username string) func(*model.User) bool {
	return func(u *model.User) bool {
		return u.Username == username
	}
}

func findUser(f func(*model.User) bool, users []model.User) (model.User, bool) {
	for i := 0; i < len(users); i++ {
		if f(&users[i]) {
			return users[i], true
		}
	}
	return model.User{}, false
}

func (c *Client) readUsers() ([]model.User, error) {
	url := c.baseURL + userPath
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.SetBasicAuth(c.username, c.password)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("Failed to read users: %s", string(body))
	}

	users := make([]model.User, 10)

	decoder := json.NewDecoder(resp.Body)
	if err = decoder.Decode(&users); err != nil {
		return nil, err
	}

	return users, nil
}

func (c *Client) CreateUser(u *model.User) (model.User, error) {
	url := c.baseURL + userPath
	userJson, err := json.Marshal(u)
	if err != nil {
		return model.User{}, err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(userJson))
	if err != nil {
		return model.User{}, err
	}

	req.SetBasicAuth(c.username, c.password)

	resp, err := c.http.Do(req)
	if err != nil {
		return model.User{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return model.User{}, fmt.Errorf("Failed to create user %s", u.Username)
	}

	users, err := c.readUsers()
	if err != nil {
		return model.User{}, err
	}

	if user, found := findUser(userByName(u.Username), users); found {
		return user, nil
	}

	return model.User{}, fmt.Errorf("User creation failed, could not fetch after create")
}

func (c *Client) UpdateUser(u *model.User) (model.User, error) {
	return c.CreateUser(u)
}

func (c *Client) DeleteUser(u *model.User) error {
	url := c.baseURL + userPath + "/" + u.Username
	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return err
	}

	req.SetBasicAuth(c.username, c.password)

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case 200:
		return nil
	case 500:
		return fmt.Errorf("User '%s' does not exist", u.Username)
	default:
		return fmt.Errorf("Unknown server-side error deleting %s", u.Username)
	}
}

func (c *Client) ReadUser(id string) (model.User, bool, error) {
	users, err := c.readUsers()
	if err != nil {
		return model.User{}, false, err
	}

	if user, found := findUser(userById(id), users); found {
		return user, true, nil
	}

	return model.User{}, false, nil
}

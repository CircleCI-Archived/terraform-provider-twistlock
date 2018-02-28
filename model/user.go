package model

import (
	"errors"
	"fmt"
	"time"
)

type UserService interface {
	CreateUser(u *User) (User, error)
	UpdateUser(u *User) (User, error)
	DeleteUser(u *User) error
	ReadUser(id string) (User, error)
}

type User struct {
	ID           string       `json:"_id"`
	Username     string       `json:"username"`
	Password     string       `json:"password"`
	Role         UserRole     `json:"role"`
	AuthType     UserAuthType `json:"authType"`
	LastModified time.Time    `json:"lastModified"`
}

type UserRole int

const (
	RoleAdmin UserRole = iota
	RoleOperator
	RoleDefenderManager
	RoleAuditor
	RoleUser
	RoleCI
)

func (r *UserRole) MarshalText() (text []byte, err error) {
	switch *r {
	case RoleAdmin:
		text = []byte("admin")
	case RoleOperator:
		text = []byte("operator")
	case RoleDefenderManager:
		text = []byte("defenderManager")
	case RoleAuditor:
		text = []byte("auditor")
	case RoleUser:
		text = []byte("user")
	case RoleCI:
		text = []byte("ci")
	default:
		err = errors.New("Attempted to MarshalText invalid UserRole")
	}

	return text, err
}

func (r *UserRole) UnmarshalText(text []byte) error {
	switch string(text) {
	case "admin":
		*r = RoleAdmin
	case "operator":
		*r = RoleOperator
	case "defenderManager":
		*r = RoleDefenderManager
	case "auditor":
		*r = RoleAuditor
	case "user":
		*r = RoleUser
	case "ci":
		*r = RoleCI
	default:
		return fmt.Errorf("Attempted to UnmarshalText invalid UserRole: %s", string(text))
	}
	return nil
}

type UserAuthType int

const (
	AuthTypeBasic UserAuthType = iota
	AuthTypeLDAP
	AuthTypeSAML
)

func (a *UserAuthType) MarshalText() (text []byte, err error) {
	switch *a {
	case AuthTypeBasic:
		text = []byte("basic")
	case AuthTypeLDAP:
		text = []byte("ldap")
	case AuthTypeSAML:
		text = []byte("saml")
	default:
		err = errors.New("Attempted to MarshalText invalid UserAuthType")
	}

	return text, err
}

func (a *UserAuthType) UnmarshalText(text []byte) error {
	switch string(text) {
	case "basic":
		*a = AuthTypeBasic
	case "ldap":
		*a = AuthTypeLDAP
	case "saml":
		*a = AuthTypeSAML
	default:
		return fmt.Errorf("Attempted to UnmarshalText invalid UserAuthType: %s", string(text))
	}
	return nil
}

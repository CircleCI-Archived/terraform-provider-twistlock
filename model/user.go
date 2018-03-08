package model

import (
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
	Password     string       `json:"password,omitempty"`
	Role         UserRole     `json:"role"`
	AuthType     UserAuthType `json:"authType"`
	LastModified time.Time    `json:"lastModified"`
}

func (u User) String() string {
	return fmt.Sprintf("{ID: %s, Username: %s, Role: %s, AuthType: %s, LastModified: %s}",
		u.ID, u.Username, u.Role, u.AuthType, u.LastModified)
}

type UserRole string

const (
	RoleAdmin           UserRole = "admin"
	RoleOperator        UserRole = "operator"
	RoleDefenderManager UserRole = "defenderManager"
	RoleAuditor         UserRole = "auditor"
	RoleUser            UserRole = "user"
	RoleCI              UserRole = "ci"
)

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
		return fmt.Errorf("Invalid UserRole: %s", string(text))
	}
	return nil
}

type UserAuthType string

const (
	AuthTypeBasic UserAuthType = "basic"
	AuthTypeLDAP  UserAuthType = "ldap"
	AuthTypeSAML  UserAuthType = "saml"
)

func (a *UserAuthType) UnmarshalText(text []byte) error {
	switch string(text) {
	case "basic":
		*a = AuthTypeBasic
	case "ldap":
		*a = AuthTypeLDAP
	case "saml":
		*a = AuthTypeSAML
	default:
		return fmt.Errorf("Invalid UserAuthType: %s", string(text))
	}
	return nil
}

package config

import (
	"fmt"
)

type Permission int

const (
	Read Permission = iota
	Write
	Flag
)

var permissionName = map[Permission]string{
	Read:  "read",
	Write: "write",
	Flag:  "flag",
}

func (p Permission) String() string {
	return permissionName[p]
}

func ParsePermission(s string) (Permission, error) {
	for k, v := range permissionName {
		if v == s {
			return k, nil
		}
	}
	return 0, fmt.Errorf("invalid permission: %s", s)
}

var Tags = struct {
	User             string
	User_Website     string
	User_Bio         string
	Url              string
	Url_Endpoint     string
	Permission       string
	Permission_Write string
	Permission_Read  string
	Permission_Flag  string
	Signature        string
	Signature_Method string
	Signature_Hash   string
}{
	User:             "::userℹ️::",
	User_Website:     "what_a_website",
	User_Bio:         "my♥️",
	Url:              "::URL::",
	Url_Endpoint:     "::endpoint::",
	Permission:       "::permissions::",
	Permission_Write: "write",
	Permission_Read:  "read",
	Permission_Flag:  "flag🚩",
	Signature:        "::✍️signature✍️",
	Signature_Method: "method",
	Signature_Hash:   "hash",
}

package database

import (
	"crypto/mlkem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/talgarr/serialize/cmd/config"
)

var baseDir = os.TempDir()

type UserInfo struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Username string `json:"username"`
}

func (u UserInfo) String() string {
	return fmt.Sprintf("Name: %s\nEmail: %s\nUsername: %s", u.Name, u.Email, u.Username)
}

type User struct {
	UserInfo      UserInfo       `json:"user_info"`
	SharedSecret  []byte         `json:"shared_secret"`
	CurrentCookie []byte         `json:"current_cookie"`
	Config        *config.Config `json:"config"`
}

func (u User) Print() {
	fmt.Println(u.UserInfo.String())
}

type Db struct {
	users map[string]*User
	dir   string
}

func NewDb() (*Db, error) {
	path, err := os.MkdirTemp(baseDir, "golabook-")
	if err != nil {
		return nil, fmt.Errorf("couldn't create a temp file: %w", err)
	}
	return &Db{
		users: make(map[string]*User),
		dir:   path,
	}, nil
}

func (db *Db) GetUser(username string) (*User, error) {
	user, ok := db.users[username]
	if !ok {
		return nil, fmt.Errorf("unkown user: %s", username)
	}
	return user, nil
}

func (db *Db) Register(name, email, username string, encapsulationKey []byte) ([]byte, error) {
	if _, err := db.GetUser(username); err == nil {
		return nil, errors.New("username already in use")
	}

	ek, err := mlkem.NewEncapsulationKey768(encapsulationKey)
	if err != nil {
		return nil, fmt.Errorf("invalid encapsulation key: %w", err)
	}

	sharedSecret, ciphertext := ek.Encapsulate()
	db.users[username] = &User{
		UserInfo: UserInfo{
			Name:     name,
			Email:    email,
			Username: username,
		},
		SharedSecret: sharedSecret,
	}

	return ciphertext, nil
}

func (db *Db) SaveConfig(user *User) error {
	data := user.Config.String()

	if err := os.WriteFile(filepath.Clean(db.dir+"/"+user.UserInfo.Username), []byte(data), 0644); err != nil {
		return fmt.Errorf("error writing file: %w", err)
	}

	return nil
}

func (db *Db) LoadConfig(user *User) error {
	data, err := os.ReadFile(filepath.Clean(db.dir + "/" + user.UserInfo.Username))
	if err != nil {
		return fmt.Errorf("error loading config: %w", err)
	}
	config, err := config.ParseConfig(string(data))
	if err != nil {
		return fmt.Errorf("error parsing file: %w", err)
	}

	user.Config = config
	return nil
}

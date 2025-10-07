package api

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/talgarr/serialize/cmd/config"
	"github.com/talgarr/serialize/cmd/database"
)

type Api struct {
	Db          *database.Db
	Dev         bool
	Flag        string
	CurrentBook string
}

func writeError(res http.ResponseWriter, message string) {
	log.Log().Msg(message)
	res.WriteHeader(http.StatusBadRequest)
	res.Write([]byte(message))
}

func (a *Api) Register(res http.ResponseWriter, req *http.Request) {
	req.ParseForm()

	username := req.PostForm.Get("username")
	if username == "" {
		log.Error().Msg("missing username")
		writeError(res, "missing username")
		return
	}

	email := req.PostForm.Get("email")
	if email == "" {
		log.Error().Msg("missing email")
		writeError(res, "missing email")
		return
	}

	name := req.PostForm.Get("name")
	if name == "" {
		log.Error().Msg("missing name")
		writeError(res, "missing name")
		return
	}

	encapsulationKey := req.PostForm.Get("encapsulationKey")
	if encapsulationKey == "" {
		log.Error().Msg("missing encapsulationKey")
		writeError(res, "missing encapsulationKey")
		return
	}

	ciphertext, err := a.Db.Register(name, email, username, []byte(encapsulationKey))
	if err != nil {
		log.Error().Msg("invalid register")
		writeError(res, "invalid register")
		return
	}

	log.Log().Str("username", username).Msg("register")
	res.WriteHeader(http.StatusOK)
	res.Write(ciphertext)
}

func (a *Api) addCookie(challenge []byte, user *database.User) {
	c1 := append(challenge, user.SharedSecret...)
	c2 := append(c1, []byte(user.UserInfo.Username)...)
	sha := sha256.Sum256(c2)
	user.CurrentCookie = sha[:]
}

func (a *Api) Login(res http.ResponseWriter, req *http.Request) {
	req.ParseForm()

	username := req.PostForm.Get("username")
	if username == "" {
		log.Error().Msg("missing username")
		writeError(res, "missing username")
		return
	}

	user, err := a.Db.GetUser(username)
	if err != nil {
		log.Error().Msg("unknown username")
		writeError(res, "unknown username")
		return
	}

	if user.Config == nil {
		if err := a.Db.LoadConfig(user); err != nil {
			log.Error().Err(err).Msg("couldn't load config for user")
		}
	}

	challenge := make([]byte, 128)
	if _, err := rand.Read(challenge); err != nil {
		log.Error().Err(err).Msg("error generating challenge")
		writeError(res, "error generating challenge")
		return
	}

	log.Log().Str("username", user.UserInfo.Username).Msg("succesfully login")
	a.addCookie(challenge, user)
	res.WriteHeader(http.StatusOK)
	res.Write(challenge)
}

func (a *Api) Logout(res http.ResponseWriter, req *http.Request) {
	req.ParseForm()

	username := req.PostForm.Get("username")
	if username == "" {
		log.Error().Msg("missing username")
		writeError(res, "missing username")
		return
	}

	user, err := a.Db.GetUser(username)
	if err != nil {
		log.Error().Err(err).Msg("unknown username")
		writeError(res, "unknown username")
		return
	}

	if err := a.checkCookie(user, req); err != nil {
		log.Error().Err(err).Msg("error check cookie")
		writeError(res, "error check cookie")
		return
	}

	user.CurrentCookie = nil

	if err := a.Db.SaveConfig(user); err != nil {
		log.Error().Err(err).Msg("error saving user")
		writeError(res, "error saving user")
		return
	}

	// Save memory
	user.Config = nil

	log.Log().Str("username", user.UserInfo.Username).Msg("logout")
	res.WriteHeader(http.StatusOK)
	res.Write([]byte("logout successfully"))
}

func (a *Api) checkCookie(user *database.User, req *http.Request) error {
	authCookie, err := req.Cookie("serialize_auth")
	if err != nil {
		return fmt.Errorf("error retrieving challenge cookie: %w", err)
	}

	cookie, err := hex.DecodeString(authCookie.Value)
	if err != nil {
		return fmt.Errorf("error decoding cookie: %w", err)
	}

	if len(cookie) != 32 {
		return errors.New("error wrong cookie length")
	}

	if !bytes.Equal(user.CurrentCookie, cookie) {
		return errors.New("wrong cookie value")
	}

	return nil
}

func (a *Api) UploadConfig(res http.ResponseWriter, req *http.Request) {
	req.ParseForm()

	username := req.PostForm.Get("username")
	if username == "" {
		log.Error().Msg("missing username")
		writeError(res, "missing username")
		return
	}

	configStr := req.PostForm.Get("config")
	if configStr == "" {
		log.Error().Msg("missing config")
		writeError(res, "missing config")
		return
	}

	user, err := a.Db.GetUser(username)
	if err != nil {
		log.Error().Err(err).Msg("unknown username")
		writeError(res, "unknown username")
		return
	}

	if err := a.checkCookie(user, req); err != nil {
		log.Error().Err(err).Msg("error check cookie")
		writeError(res, "error check cookie")
		return
	}

	configDecoded, err := hex.DecodeString(configStr)
	if err != nil {
		log.Error().Err(err).Msg("error decoding hex config")
		writeError(res, "error decoding hex config")
		return
	}

	config, err := config.ParseConfig(string(configDecoded))
	if err != nil {
		log.Error().Err(err).Msg("error parsing config")
		writeError(res, "error parsing config")
		return
	}

	if !a.Dev && config.Permissions.V.Flag.V {
		log.Error().Msg("invalid permission in prod")
		writeError(res, "invalid permission in prod")
		return
	}

	if !config.VerifySignature(user.SharedSecret) {
		log.Error().Msg("signature verification failed")
		writeError(res, "signature verification failed")
		return
	}

	user.Config = config

	res.WriteHeader(http.StatusOK)
	res.Write([]byte("upload config successfully"))
}

func (a *Api) WriteBook(res http.ResponseWriter, req *http.Request) {
	req.ParseForm()

	username := req.PostForm.Get("username")
	if username == "" {
		log.Error().Msg("missing username")
		writeError(res, "missing username")
		return
	}

	entry := req.PostForm.Get("entry")
	if entry == "" {
		log.Error().Msg("missing entry")
		writeError(res, "missing entry")
		return
	}

	user, err := a.Db.GetUser(username)
	if err != nil {
		log.Error().Err(err).Msg("unknown username")
		writeError(res, "unknown username")
		return
	}

	if err := a.checkCookie(user, req); err != nil {
		log.Error().Err(err).Msg("error check cookie")
		writeError(res, "error check cookie")
		return
	}

	if !user.Config.Permissions.V.Write.V {
		log.Error().Msg("config doesn't have write permission")
		writeError(res, "config doesn't have write permission")
		return
	}

	if !user.Config.VerifySignature(user.SharedSecret) {
		log.Error().Msg("invalid signature of config")
		writeError(res, "invalid signature of config")
		return
	}

	a.CurrentBook += time.Now().Local().Format(time.RFC3339) + " => " + entry + "\n\n"
	res.WriteHeader(http.StatusOK)
	res.Write([]byte("added entry to book"))
}

func (a *Api) ReadBook(res http.ResponseWriter, req *http.Request) {
	req.ParseForm()

	username := req.PostForm.Get("username")
	if username == "" {
		log.Error().Msg("missing username")
		writeError(res, "missing username")
		return
	}

	user, err := a.Db.GetUser(username)
	if err != nil {
		log.Error().Err(err).Msg("unknown username")
		writeError(res, "unknown username")
		return
	}

	if err := a.checkCookie(user, req); err != nil {
		log.Error().Err(err).Msg("error check cookie")
		writeError(res, "error check cookie")
		return
	}

	if !user.Config.VerifySignature(user.SharedSecret) {
		log.Error().Msg("invalid signature of config")
		writeError(res, "invalid signature of config")
		return
	}

	body := ""
	if user.Config.Permissions.V.Read.V {
		body += a.CurrentBook
	}

	if user.Config.Permissions.V.Flag.V {
		body += "Flag: " + a.Flag
	}

	res.WriteHeader(http.StatusOK)
	res.Write([]byte(body))
}

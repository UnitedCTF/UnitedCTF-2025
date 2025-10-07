package config

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/talgarr/serialize/cmd/utils"
)

func TestConfig_parseUser(t *testing.T) {
	type args struct {
		start int
		s     string
	}
	tests := []struct {
		name         string
		args         args
		wantErr      bool
		wantUser     User
		wantRemain   string
		wantComments []utils.Index[string]
	}{
		{
			name: "No comment",
			args: args{
				start: 0,
				s:     "my♥️🍏this is my bio\nwhat_a_website🍏http://test.com\n🍎\n",
			},
			wantErr: false,
			wantUser: User{
				Bio:     utils.Index[string]{V: "this is my bio", I: 0},
				Website: utils.Index[string]{V: "http://test.com", I: 20},
			},
			wantRemain:   "",
			wantComments: []utils.Index[string]{},
		},
		{
			name: "Comment",
			args: args{
				start: 0,
				s:     "my♥️🍏this is💬nistrato💬 my bio\nwhat_a_website🍏http://test.com\n🍎\n",
			},
			wantErr: false,
			wantUser: User{
				Bio:     utils.Index[string]{V: "this is my bio", I: 0},
				Website: utils.Index[string]{V: "http://test.com", I: 20},
			},
			wantRemain: "",
			wantComments: []utils.Index[string]{
				{
					I: 12,
					V: "nistrato",
				},
			},
		},
		{
			name: "Multiple comment",
			args: args{
				start: 0,
				s:     "my♥️🍏this i💬kajshda98sd98h3___::testjkashkj::name::🍎:💬s my bio\nwhat_a_w💬8ahj9uin32kj89\"\"::email::💬ebsite🍏http://test.com\n🍎\n",
			},
			wantErr: false,
			wantUser: User{
				Bio:     utils.Index[string]{V: "this is my bio", I: 0},
				Website: utils.Index[string]{V: "http://test.com", I: 20},
			},
			wantRemain: "",
			wantComments: []utils.Index[string]{
				{
					I: 11,
					V: "kajshda98sd98h3___::testjkashkj::name::🍎:",
				},
				{
					I: 71,
					V: "8ahj9uin32kj89\"\"::email::",
				},
			},
		},
		{
			name: "Offset",
			args: args{
				start: 2,
				s:     "28my♥️🍏this is my bio\nwhat_a_website🍏http://test.com\n🍎\n",
			},
			wantErr: false,
			wantUser: User{
				Bio:     utils.Index[string]{V: "this is my bio", I: 0},
				Website: utils.Index[string]{V: "http://test.com", I: 20},
			},
			wantRemain: "",
		},
		{
			name: "Offset with comment",
			args: args{
				start: 2,
				s:     "20my♥️🍏this is💬nistrato💬 my bio\nwhat_a_website🍏http://test.com\n🍎\n",
			},
			wantErr: false,
			wantUser: User{
				Bio:     utils.Index[string]{V: "this is my bio", I: 0},
				Website: utils.Index[string]{V: "http://test.com", I: 20},
			},
			wantRemain: "",
			wantComments: []utils.Index[string]{
				{
					I: 14,
					V: "nistrato",
				},
			},
		},
		{
			name: "Offset with comment and remain",
			args: args{
				start: 2,
				s:     "99my♥️🍏this is💬nistrato💬 my bio\nwhat_a_website🍏http://test.com\n🍎\nstuff",
			},
			wantErr: false,
			wantUser: User{
				Bio:     utils.Index[string]{V: "this is my bio", I: 0},
				Website: utils.Index[string]{V: "http://test.com", I: 20},
			},
			wantRemain: "stuff",
			wantComments: []utils.Index[string]{
				{
					I: 16,
					V: "nistrato",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Config{}
			iter := []rune(tt.args.s)
			got, err := c.parseUser(tt.args.start, iter)
			if (err != nil) != tt.wantErr {
				t.Errorf("Config.parseUser() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if c.User.V.Bio.V != tt.wantUser.Bio.V {
				t.Errorf("Config.parseUser() = %v, want %v", c.User.V.Bio, tt.wantUser.Bio)
			}
			if c.User.V.Website.V != tt.wantUser.Website.V {
				t.Errorf("Config.parseUser() = %v, want %v", c.User.V.Website, tt.wantUser.Website)
			}
			if string(iter[got:]) != tt.wantRemain {
				t.Errorf("Config.parseUser() = %v, want %v", string(iter[got:]), tt.wantRemain)
			}

			if len(tt.wantComments) != len(c.Comments) {
				t.Errorf("wrong comments lenght = %d, want %d", len(tt.wantComments), len(c.Comments))
				return
			}
			for i, com := range tt.wantComments {
				if c.Comments[i].V != com.V {
					t.Errorf("wrong comment content = %s, want %s", c.Comments[i].V, com.V)
				}
			}
		})
	}
}

func TestVerifySignatureSha3(t *testing.T) {
	type Test struct {
		name   string
		config *Config
		key    []byte
		valid  bool
	}

	config := Config{
		User: utils.Index[User]{
			V: User{
				Bio:     utils.Index[string]{V: "a"},
				Website: utils.Index[string]{V: "b"},
			},
		},
		Url: utils.Index[Url]{
			V: Url{Endpoint: utils.Index[string]{V: "c"}},
		},
		Permissions: utils.Index[Permissions]{
			V: Permissions{
				Write: utils.Index[bool]{V: true},
				Read:  utils.Index[bool]{V: true},
				Flag:  utils.Index[bool]{V: false},
			},
		},
		Signature: utils.Index[Signature]{
			V: Signature{
				Method: utils.Index[string]{V: "sha3"},
				Hash:   utils.Index[[]byte]{V: []byte("\x55\x31\x30\xae\x29\x91\xfe\x37\x1a\x13\x74\x7f\xbd\x1c\xf7\x6e\xc1\x7f\xd2\x43\xe3\x26\x36\x05\xc2\xf6\xdb\xf4\xc4\x81\x33\xc8")},
			},
		},
		Comments: []utils.Index[string]{},
	}

	config_bio := config
	config_bio.User.V.Bio.V = "z"

	config_web := config
	config_web.User.V.Website.V = "z"

	config_url := config
	config_url.Url.V.Endpoint.V = "z"

	config_perm_write := config
	config_perm_write.Permissions.V.Write.V = false

	config_perm_read := config
	config_perm_read.Permissions.V.Read.V = false

	config_perm_flag := config
	config_perm_flag.Permissions.V.Flag.V = true

	config_key := config
	config_key.Signature.V.Hash.V = []byte("\x13\x37\x13\x37\x13\x37\x13\x37\x13\x37\x13\x37\x13\x37\x13\x37\x13\x37\x13\x37\x13\x37\x13\x37\x13\x37\x13\x37\x13\x37\x13\x37")

	config_hash := config
	config_hash.Signature.V.Method.V = "sha256"

	config_comment := config
	config_comment.Comments = append(config_comment.Comments, utils.Index[string]{I: 0, V: "comment"})

	tests := []Test{
		{
			name:   "No tempered with signature",
			config: &config,
			key:    []byte("abcdef"),
			valid:  true,
		},
		{
			name:   "Modify bio",
			config: &config_bio,
			key:    []byte("abcdef"),
			valid:  false,
		},
		{
			name:   "Modify website",
			config: &config_web,
			key:    []byte("abcdef"),
			valid:  false,
		},
		{
			name:   "Modify permission write",
			config: &config_perm_write,
			key:    []byte("abcdef"),
			valid:  false,
		},
		{
			name:   "Modify permission read",
			config: &config_perm_read,
			key:    []byte("abcdef"),
			valid:  false,
		},
		{
			name:   "Modify permission flag",
			config: &config_perm_flag,
			key:    []byte("abcdef"),
			valid:  false,
		},
		{
			name:   "Modify comment",
			config: &config_comment,
			key:    []byte("abcdef"),
			valid:  true,
		},
		{
			name:   "Modify endpoint",
			config: &config_url,
			key:    []byte("abcdef"),
			valid:  false,
		},
		{
			name:   "Modify key",
			config: &config,
			key:    []byte("dddddd"),
			valid:  false,
		},
		{
			name:   "Modify hash method",
			config: &config_hash,
			key:    []byte("abcdef"),
			valid:  false,
		},
		{
			name:   "Tempered with signature",
			config: &config_key,
			key:    []byte("abcdef"),
			valid:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid := tt.config.VerifySignature(tt.key)
			if valid != tt.valid {
				t.Errorf("expected %t, got %t", tt.valid, valid)
			}
		})
	}
}
func TestVerifySignatureSha256(t *testing.T) {
	type Test struct {
		name   string
		config *Config
		key    []byte
		valid  bool
	}

	config := Config{
		User: utils.Index[User]{
			V: User{
				Bio:     utils.Index[string]{V: "a"},
				Website: utils.Index[string]{V: "b"},
			},
		},
		Url: utils.Index[Url]{
			V: Url{Endpoint: utils.Index[string]{V: "c"}},
		},
		Permissions: utils.Index[Permissions]{
			V: Permissions{
				Write: utils.Index[bool]{V: true},
				Read:  utils.Index[bool]{V: true},
				Flag:  utils.Index[bool]{V: false},
			},
		},
		Signature: utils.Index[Signature]{
			V: Signature{
				Method: utils.Index[string]{V: "sha256"},
				Hash:   utils.Index[[]byte]{V: []byte("\xc6\x05\x43\xa9\xa3\xd2\xa0\xe7\x09\xc9\x99\xe6\xa8\x19\x4a\x6f\x15\xd5\x23\xe7\x2a\xb0\x03\xa7\x5c\x92\x41\xb3\xa6\xc0\x77\xd6")},
			},
		},
		Comments: []utils.Index[string]{},
	}

	config_bio := config
	config_bio.User.V.Bio.V = "z"

	config_web := config
	config_web.User.V.Website.V = "z"

	config_url := config
	config_url.Url.V.Endpoint.V = "z"

	config_perm_write := config
	config_perm_write.Permissions.V.Write.V = false

	config_perm_read := config
	config_perm_read.Permissions.V.Read.V = false

	config_perm_flag := config
	config_perm_flag.Permissions.V.Flag.V = true

	config_key := config
	config_key.Signature.V.Hash.V = []byte("\x13\x37\x13\x37\x13\x37\x13\x37\x13\x37\x13\x37\x13\x37\x13\x37\x13\x37\x13\x37\x13\x37\x13\x37\x13\x37\x13\x37\x13\x37\x13\x37")

	config_hash := config
	config_hash.Signature.V.Method.V = "sha3"

	config_comment := config
	config_comment.Comments = append(config_comment.Comments, utils.Index[string]{I: 0, V: "comment"})

	tests := []Test{
		{
			name:   "No tempered with signature",
			config: &config,
			key:    []byte("abcdef"),
			valid:  true,
		},
		{
			name:   "Modify bio",
			config: &config_bio,
			key:    []byte("abcdef"),
			valid:  false,
		},
		{
			name:   "Modify website",
			config: &config_web,
			key:    []byte("abcdef"),
			valid:  false,
		},
		{
			name:   "Modify permission write",
			config: &config_perm_write,
			key:    []byte("abcdef"),
			valid:  false,
		},
		{
			name:   "Modify permission read",
			config: &config_perm_read,
			key:    []byte("abcdef"),
			valid:  false,
		},
		{
			name:   "Modify permission flag",
			config: &config_perm_flag,
			key:    []byte("abcdef"),
			valid:  false,
		},
		{
			name:   "Modify comment",
			config: &config_comment,
			key:    []byte("abcdef"),
			valid:  true,
		},
		{
			name:   "Modify endpoint",
			config: &config_url,
			key:    []byte("abcdef"),
			valid:  false,
		},
		{
			name:   "Modify key",
			config: &config,
			key:    []byte("dddddd"),
			valid:  false,
		},
		{
			name:   "Modify hash method",
			config: &config_hash,
			key:    []byte("abcdef"),
			valid:  false,
		},
		{
			name:   "Tempered with signature",
			config: &config_key,
			key:    []byte("abcdef"),
			valid:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid := tt.config.VerifySignature(tt.key)
			if valid != tt.valid {
				t.Errorf("expected %t, got %t", tt.valid, valid)
			}
		})
	}
}

func TestParseConfig(t *testing.T) {
	type args struct {
		s string
	}
	type Test struct {
		name    string
		args    args
		want    *Config
		wantErr bool
	}
	tests := []Test{
		{
			name: "Offset with comment",
			args: args{
				s: `::userℹ️::
my♥️🍏this is m💬nistrato💬y bio
what_a_website🍏http://test.com
🍎
::URL::
::endpoint::🍏https://exa'💬mple.com

sup'
🍎
::permissions::
write🍏True
read🍏True
flag💬X🍏True
🍎
::✍️signature✍️
method🍏💬🚩🍏False
🍎
::✍️signature✍️
method🍏sha256
hash🍏019283712ab879d080ef098e
`,
			},
			wantErr: false,
			want: &Config{
				User: utils.Index[User]{
					V: User{
						Bio:     utils.Index[string]{V: "this is my bio"},
						Website: utils.Index[string]{V: "http://test.com"},
					},
				},
				Url: utils.Index[Url]{
					V: Url{Endpoint: utils.Index[string]{V: "https://exa💬mple.com\n\nsup"}},
				},
				Permissions: utils.Index[Permissions]{
					V: Permissions{
						Write: utils.Index[bool]{V: true},
						Read:  utils.Index[bool]{V: true},
						Flag:  utils.Index[bool]{V: false},
					},
				},
				Signature: utils.Index[Signature]{
					V: Signature{
						Method: utils.Index[string]{V: "sha256"},
						Hash:   utils.Index[[]byte]{V: []byte("\x01\x92\x83\x71\x2a\xb8\x79\xd0\x80\xef\x09\x8e")},
					},
				},
				Comments: []utils.Index[string]{
					{V: "nistrato"},
					{V: "X🍏True\n🍎\n::✍️signature✍️\nmethod🍏"},
				},
			},
		},
		{
			name: "Exploit",
			args: args{
				s: `::userℹ️::
my♥️🍏a
what_a_website🍏b'"
🍎
::permissions::
write🍏True
read🍏True
flag🚩🍏True
🍎
::URL::
::endpoint::🍏c
🍎
::✍️signature✍️
method🍏sha256
hash🍏019283712ab879d080ef098e
💬'
🍎
::permissions::
write🍏True
read🍏True
flag🚩🍏False
🍎
::URL::
::endpoint::🍏c
🍎
::✍️signature✍️
method🍏sha256
hash🍏019283712ab879d080ef098e
`,
			},
			wantErr: false,
			want: &Config{
				User: utils.Index[User]{
					V: User{
						Bio: utils.Index[string]{V: "a"},
						Website: utils.Index[string]{V: `b"
🍎
::permissions::
write🍏True
read🍏True
flag🚩🍏True
🍎
::URL::
::endpoint::🍏c
🍎
::✍️signature✍️
method🍏sha256
hash🍏019283712ab879d080ef098e
💬`},
					},
				},
				Url: utils.Index[Url]{
					V: Url{Endpoint: utils.Index[string]{V: `c`}},
				},
				Permissions: utils.Index[Permissions]{
					V: Permissions{
						Write: utils.Index[bool]{V: true},
						Read:  utils.Index[bool]{V: true},
						Flag:  utils.Index[bool]{V: false},
					},
				},
				Signature: utils.Index[Signature]{
					V: Signature{
						Method: utils.Index[string]{V: "sha256"},
						Hash:   utils.Index[[]byte]{V: []byte("\x01\x92\x83\x71\x2a\xb8\x79\xd0\x80\xef\x09\x8e")},
					},
				},
				Comments: []utils.Index[string]{},
			},
		},
	}
	isEqual := func(c *Config, tt Test) {
		if c.User.V.Bio.V != tt.want.User.V.Bio.V {
			t.Errorf("Config.parseUser() = %v, want %v", c.User.V.Bio, tt.want.User.V.Bio)
		}
		if c.User.V.Website.V != tt.want.User.V.Website.V {
			t.Errorf("Config.parseUser() = %v, want %v", c.User.V.Website, tt.want.User.V.Website)
		}
		if tt.want.Url.V.Endpoint.V != c.Url.V.Endpoint.V {
			t.Errorf("error %v, want %v", tt.want.Url.V.Endpoint, c.Url.V.Endpoint)
		}
		if tt.want.Permissions.V.Read.V != c.Permissions.V.Read.V {
			t.Errorf("error read")
		}
		if tt.want.Permissions.V.Write.V != c.Permissions.V.Write.V {
			t.Errorf("error write")
		}
		if tt.want.Permissions.V.Flag.V != c.Permissions.V.Flag.V {
			t.Errorf("error flag")
		}
		if tt.want.Signature.V.Method.V != c.Signature.V.Method.V {
			t.Errorf("error %v, want %v", tt.want.Signature.V.Method.V, c.Signature.V.Method.V)
		}

		if !bytes.Equal(c.Signature.V.Hash.V, tt.want.Signature.V.Hash.V) {
			t.Errorf("error %s, want %s", hex.EncodeToString(tt.want.Signature.V.Hash.V), hex.EncodeToString(c.Signature.V.Hash.V))
		}
		for i, comment := range tt.want.Comments {
			if comment.V != c.Comments[i].V {
				t.Errorf("error %s, want %s", comment.V, c.Comments[i].V)
			}
		}
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := ParseConfig(tt.args.s)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseConfig() error = %v, wantErr %v", err, tt.wantErr)
				}
				return
			}
			isEqual(c, tt)
			str := c.String()
			c2, err := ParseConfig(str)
			if err != nil {
				t.Error(str)
				t.Error(fmt.Errorf("error reparsing: %w", err))
				return
			}
			isEqual(c2, tt)
		})
	}
}

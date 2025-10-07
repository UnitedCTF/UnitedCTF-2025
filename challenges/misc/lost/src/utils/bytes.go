package utils

import (
	"bytes"
	"io"
)

func ReadN(r io.Reader, n int) ([]byte, error) {
	p := make([]byte, n)
	_, err := r.Read(p)
	if err != nil {
		return nil, err
	}
	return p, nil
}

func TrimNull(b []byte) []byte {
	index := bytes.IndexByte(b, 0)
	if index == -1 {
		return b[:]
	}
	return b[:bytes.IndexByte(b, 0)]
}

package utils

import "encoding/hex"

type Index[T any] struct {
	I int
	V T
}

func BoolIndexToString(i Index[bool]) Index[string] {
	s := "False"
	if i.V {
		s = "True"
	}
	return Index[string]{I: i.I, V: s}
}

func ByteIndexToHexString(i Index[[]byte]) Index[string] {
	return Index[string]{
		I: i.I,
		V: hex.EncodeToString(i.V),
	}
}

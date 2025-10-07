package utils

func Stub[T any](val T, err error) T {
	return val
}

func StubPanic[T any](val T, err error) T {
	if err != nil {
		panic(err)
	}
	return val
}

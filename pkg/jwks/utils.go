package jwks

import "encoding/json"

func marshaler2JSON[T any, U any](data T, fn func(T) (U, error)) (string, error) {
	m, err := fn(data)
	if err != nil {
		return "", err
	}

	str, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	return string(str), nil
}

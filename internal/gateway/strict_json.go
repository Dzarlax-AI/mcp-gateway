package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

var errInvalidStrictJSON = errors.New("invalid JSON")

// rejectDuplicateJSONKeys validates one JSON value and rejects repeated object
// keys at every depth. Repeated values in arrays remain valid JSON.
func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := consumeStrictJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errInvalidStrictJSON
	}
	return nil
}

func consumeStrictJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return errInvalidStrictJSON
	}
	delim, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return errInvalidStrictJSON
			}
			key, ok := keyToken.(string)
			if !ok {
				return errInvalidStrictJSON
			}
			if _, exists := seen[key]; exists {
				return errInvalidStrictJSON
			}
			seen[key] = struct{}{}
			if err := consumeStrictJSONValue(decoder); err != nil {
				return err
			}
		}
		if _, err := decoder.Token(); err != nil { // closing brace
			return errInvalidStrictJSON
		}
	case '[':
		for decoder.More() {
			if err := consumeStrictJSONValue(decoder); err != nil {
				return err
			}
		}
		if _, err := decoder.Token(); err != nil { // closing bracket
			return errInvalidStrictJSON
		}
	default:
		return errInvalidStrictJSON
	}
	return nil
}

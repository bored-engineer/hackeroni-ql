package h1

import (
	"encoding/json"
	"net/url"
)

// URI extends *net.URL with JSON parsing
type URI struct {
	*net.URL
}

// UnmarshalJSON decodes as a string then parses as a URL
func (u *URL) UnmarshalJSON(data []byte) (err error) {
	var str string
	err = json.Unmarshal(data, &str)
	if err != nil {
		return err
	}
	u.URL, err = url.Parse(str)
	if err != nil {
		return err
	}
	return nil
}
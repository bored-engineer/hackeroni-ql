package h1

import (
	"encoding/json"
	"time"
)

// DateTime extends time.Time with JSON parsing
type DateTime struct {
	*time.Time
}

// UnmarshalJSON helps unmarshal ISO8601 dates in JSON
func (d *DateTime) UnmarshalJSON(data []byte) (err error) {
	var str string
	err = json.Unmarshal(data, &str)
	if err != nil {
		return err
	}
	time, err := time.Parse(time.RFC3339, str)
	d.Time = &t
	return err
}

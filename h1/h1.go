package h1

// Bool allocates a new bool value to store v at and returns a pointer to it.
func Bool(v bool) *bool { return &v }

// String allocates a new bool value to store v at and returns a pointer to it.
func String(v string) *string { return &v }

// Int allocates a new bool value to store v at and returns a pointer to it.
func Int(v int32) *int32 { return &v }

// Float allocates a new float64 value to store v at and returns a pointer to it.
func Float(v float64) *float64 { return &v }
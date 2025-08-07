package int

import (
	"encoding/gob"
)

// init registers the Int type with the gob package.
// This enables gob encoding/decoding of Int either directly or when embedded in other structs.
// Without this registration, gob encoding would fail when Int types are encountered.
func init() {
	gob.Register(Int{})
}

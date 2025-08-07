package paillier

import (
	"encoding/gob"
)

// init registers Paillier key types with the gob package.
// This enables gob encoding/decoding of these types either directly or when embedded in other structs.
// Without this registration, gob encoding would fail when these types are encountered.
func init() {
	gob.Register(PrivateKey{})
	gob.Register(PublicKey{})
}

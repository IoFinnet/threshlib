package keygen

import (
	"bytes"
	"encoding/gob"
)

// init registers ECDSA keygen types with the gob package.
// This enables gob encoding/decoding of these types either directly or when embedded in other structs.
// Without this registration, gob encoding would fail when these types are encountered.
// This is especially important for the Copy() method which uses gob for deep copying.
func init() {
	gob.Register(LocalPartySaveData{})
	gob.Register(LocalPreParams{})
	gob.Register(LocalSecrets{})
}

// Copy creates a deep copy of the LocalPartySaveData using Gob encoding/decoding
func (save LocalPartySaveData) Copy() LocalPartySaveData {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	dec := gob.NewDecoder(&buf)

	err := enc.Encode(save)
	if err != nil {
		panic(err)
	}

	var newData LocalPartySaveData
	err = dec.Decode(&newData)
	if err != nil {
		panic(err)
	}

	return newData
}

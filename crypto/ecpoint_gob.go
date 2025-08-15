package crypto

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"fmt"

	big "github.com/iofinnet/tss-lib/v3/common/int"
	"github.com/iofinnet/tss-lib/v3/tss"
)

// init registers the ECPoint type with the gob package.
// This enables gob encoding/decoding of ECPoint either directly or when embedded in other structs.
// Without this registration, gob encoding would fail when ECPoint types are encountered.
// ECPoint also implements custom GobEncoder and GobDecoder interfaces for proper serialization.
func init() {
	gob.Register(ECPoint{})
}

// ECPoint supports various marshaling formats implemented as custom encoder/decoders.
var (
	_ gob.GobEncoder = (*ECPoint)(nil)
	_ gob.GobDecoder = (*ECPoint)(nil)
)

// ----- //
// Gob helpers for if you choose to encode messages with Gob.

func (P *ECPoint) GobEncode() ([]byte, error) {
	buf := &bytes.Buffer{}

	// Get curve name
	ecName, ok := tss.GetCurveName(P.curve)
	if !ok {
		return nil, fmt.Errorf("cannot find %T name in curve registry", P.curve)
	}

	// Encode curve name
	curveNameBytes := []byte(ecName)
	if err := binary.Write(buf, binary.LittleEndian, uint32(len(curveNameBytes))); err != nil {
		return nil, err
	}
	if _, err := buf.Write(curveNameBytes); err != nil {
		return nil, err
	}

	// Encode X coordinate
	x, err := P.coords[0].GobEncode()
	if err != nil {
		return nil, err
	}
	if err2 := binary.Write(buf, binary.LittleEndian, uint32(len(x))); err2 != nil {
		return nil, err2
	}
	if _, err2 := buf.Write(x); err2 != nil {
		return nil, err2
	}

	// Encode Y coordinate
	y, err := P.coords[1].GobEncode()
	if err != nil {
		return nil, err
	}
	if err2 := binary.Write(buf, binary.LittleEndian, uint32(len(y))); err2 != nil {
		return nil, err2
	}
	if _, err2 := buf.Write(y); err2 != nil {
		return nil, err2
	}
	return buf.Bytes(), nil
}

func (P *ECPoint) GobDecode(buf []byte) error {
	reader := bytes.NewReader(buf)

	// Decode curve name
	var curveNameLength uint32
	if err := binary.Read(reader, binary.LittleEndian, &curveNameLength); err != nil {
		return err
	}
	curveNameBytes := make([]byte, curveNameLength)
	if _, err := reader.Read(curveNameBytes); err != nil {
		return fmt.Errorf("gob decode failed: %v", err)
	}
	curveName := string(curveNameBytes)

	// Get curve from name
	curve, ok := tss.GetCurveByName(tss.CurveName(curveName))
	if !ok {
		return fmt.Errorf("cannot find curve named %s in curve registry", curveName)
	}

	// Decode X coordinate
	var xLength uint32
	if err := binary.Read(reader, binary.LittleEndian, &xLength); err != nil {
		return err
	}
	x := make([]byte, xLength)
	if _, err := reader.Read(x); err != nil {
		return fmt.Errorf("gob decode failed: %v", err)
	}
	X := new(big.Int)
	if err := X.GobDecode(x); err != nil {
		return err
	}

	// Decode Y coordinate
	var yLength uint32
	if err := binary.Read(reader, binary.LittleEndian, &yLength); err != nil {
		return err
	}
	y := make([]byte, yLength)
	if _, err := reader.Read(y); err != nil {
		return fmt.Errorf("gob decode failed: %v", err)
	}
	Y := new(big.Int)
	if err := Y.GobDecode(y); err != nil {
		return err
	}

	// Set ECPoint values
	P.curve = curve
	P.coords = [2]*big.Int{X, Y}

	// Validate point is on curve
	if !P.IsOnCurve() {
		return fmt.Errorf("decoded point is not on the elliptic curve (%T)", P.curve)
	}
	return nil
}

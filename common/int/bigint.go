// Optionally constant time big.Int (best effort)

package int

import (
	"encoding/json"
	"math/big"
	"sync"

	big_const "github.com/cronokirby/saferith"
)

type (
	Int struct {
		i     *big_const.Int
		i2    *big.Int
		mutex *sync.RWMutex
	}
)

var (
	constantTimeIntEnabled = false
)

// EnableConstantTimeArithmetic enables best-effort constant time arithmetic (experimental, probably slow)
// Must be called before any LocalParty constructor or protocol is used, or behaviour may be unpredictable.
func EnableConstantTimeArithmetic() (enabled bool) {
	constantTimeIntEnabled = true
	return constantTimeIntEnabled
}

func NewInt(x uint64) *Int {
	i := new(big_const.Int).SetUint64(x)
	return &Int{i, i.Big(), new(sync.RWMutex)}
}

func Wrap(i2 *big.Int) *Int {
	i := new(big_const.Int).SetBytes(i2.Bytes())
	if i2.Cmp(zero.Big()) < 0 {
		i = i.Neg(1)
	}
	return &Int{i, i2, new(sync.RWMutex)}
}

func (z *Int) Set(x *Int) *Int {
	z.ensureInitialized()
	x.ensureInitialized()
	z.mutex.Lock()
	defer z.mutex.Unlock()
	if constantTimeIntEnabled {
		z.i = z.i.SetBytes(x.Bytes())
	} else {
		z.i2 = z.i2.SetBytes(x.Bytes())
	}
	return z
}
func (z *Int) SetBytes(data []byte) *Int {
	z.ensureInitialized()
	z.mutex.Lock()
	defer z.mutex.Unlock()
	if constantTimeIntEnabled {
		z.i = z.i.SetBytes(data)
	} else {
		z.i2 = z.i2.SetBytes(data)
	}
	return z
}
func (z *Int) SetInt64(x int64) *Int {
	if x < 0 {
		panic("SetInt64 used with a negative int64")
	}
	z.ensureInitialized()
	z.mutex.Lock()
	defer z.mutex.Unlock()
	if constantTimeIntEnabled {
		z.i = z.i.SetUint64(uint64(x))
	} else {
		z.i2 = z.i2.SetUint64(uint64(x))
	}
	return z
}
func (z *Int) SetUint64(x uint64) *Int {
	z.ensureInitialized()
	z.mutex.Lock()
	defer z.mutex.Unlock()
	if constantTimeIntEnabled {
		z.i = z.i.SetUint64(x)
	} else {
		z.i2 = z.i2.SetUint64(x)
	}
	return z
}
func (z *Int) Clone() *Int {
	z.ensureInitialized()
	z.mutex.Lock()
	defer z.mutex.Unlock()
	cloned := new(Int)
	if constantTimeIntEnabled {
		cloned.i = z.i.Clone()
	} else {
		cloned.i2 = new(big.Int).SetBytes(z.i2.Bytes())
	}
	return cloned
}
func (z *Int) Cmp(y *Int) (r int) {
	z.ensureInitialized()
	y.ensureInitialized()
	return z.Big().Cmp(y.Big())
}
func (z *Int) BitLen() int {
	z.ensureInitialized()
	z.mutex.RLock()
	defer z.mutex.RUnlock()
	if !constantTimeIntEnabled {
		return z.i2.BitLen()
	}
	// TODO: this leaks the value, but AnnouncedLen will not work for generating primes.
	return z.i.TrueLen()
}
func (z *Int) Neg(x *Int) *Int {
	z.ensureInitialized()
	x.ensureInitialized()
	z.mutex.Lock()
	defer z.mutex.Unlock()
	if constantTimeIntEnabled {
		// allocate a new *Int otherwise we will mutate arg `x`
		z.i = x.Clone().i.Neg(1)
	} else {
		z.i2 = z.i2.Neg(x.i2)
	}
	return z
}
func (z *Int) SetNeg() *Int {
	z.ensureInitialized()
	z.mutex.Lock()
	defer z.mutex.Unlock()
	if constantTimeIntEnabled {
		z.i = z.i.Neg(1)
	} else {
		z.i2 = z.i2.Neg(z.i2)
	}
	return z
}
func (z *Int) SetInt(x *Int) *Int {
	z.ensureInitialized()
	x.ensureInitialized()
	z.mutex.Lock()
	defer z.mutex.Unlock()
	z.i = x.i
	z.i2 = x.i2
	return z
}
func (z *Int) Add(x, y *Int) *Int {
	z.ensureInitialized()
	x.ensureInitialized()
	y.ensureInitialized()
	z.mutex.Lock()
	defer z.mutex.Unlock()
	if constantTimeIntEnabled {
		z.i = z.i.Add(x.i, y.i, -1)
	} else {
		z.i2 = z.i2.Add(x.i2, y.i2)
	}
	return z
}
func (z *Int) Mul(x, y *Int) *Int {
	z.ensureInitialized()
	x.ensureInitialized()
	y.ensureInitialized()
	z.mutex.Lock()
	defer z.mutex.Unlock()
	if constantTimeIntEnabled {
		z.i = z.i.Clone().Mul(x.i.Clone(), y.i.Clone(), -1)
	} else {
		z.i2 = z.i2.Mul(x.i2, y.i2)
	}
	return z
}
func (z *Int) Mod(x, y *Int) *Int {
	z.ensureInitialized()
	x.ensureInitialized()
	y.ensureInitialized()
	z.mutex.Lock()
	defer z.mutex.Unlock()
	if constantTimeIntEnabled {
		z.i = z.i.SetBytes(x.i.Mod(big_const.ModulusFromBytes(y.Bytes())).Bytes())
	} else {
		z.i2 = z.i2.Mod(x.i2, y.i2)
	}
	return z
}
func (z *Int) String() string {
	z.ensureInitialized()
	z.mutex.RLock()
	defer z.mutex.RUnlock()
	if constantTimeIntEnabled {
		return z.i.String()
	} else {
		return z.i2.String()
	}
}

// TODO: DANGER ZONE! Potentially non constant-time. Revisit
func (z *Int) SetBit(x *Int, i int, b uint) *Int {
	z.ensureInitialized()
	x.ensureInitialized()
	bi := new(big.Int).SetBit(x.Big(), i, b)
	return z.wrap(bi)
}
func (z *Int) Sub(x, y *Int) *Int {
	z.ensureInitialized()
	x.ensureInitialized()
	y.ensureInitialized()
	bi := new(big.Int).Sub(x.Big(), y.Big())
	return z.wrap(bi)
}
func (z *Int) Div(x, y *Int) *Int {
	z.ensureInitialized()
	x.ensureInitialized()
	y.ensureInitialized()
	bi := new(big.Int).Div(x.Big(), y.Big())
	return z.wrap(bi)
}
func (z *Int) Exp(x, y, m *Int) *Int {
	z.ensureInitialized()
	x.ensureInitialized()
	y.ensureInitialized()
	var bi *big.Int
	if m == nil {
		bi = new(big.Int).Exp(x.Big(), y.Big(), nil)
	} else {
		bi = new(big.Int).Exp(x.Big(), y.Big(), m.Big())
	}
	return z.wrap(bi)
}
func (z *Int) ModInverse(x, m *Int) *Int {
	z.ensureInitialized()
	x.ensureInitialized()
	m.ensureInitialized()
	bi := new(big.Int).ModInverse(x.Big(), m.Big())
	return z.wrap(bi)
}
func (z *Int) Sqrt(x *Int) *Int {
	z.ensureInitialized()
	x.ensureInitialized()
	bi := new(big.Int).Sqrt(x.Big())
	return z.wrap(bi)

}
func (z *Int) ModSqrt(x, m *Int) *Int {
	z.ensureInitialized()
	x.ensureInitialized()
	m.ensureInitialized()
	bi := new(big.Int).ModSqrt(x.Big(), m.Big())
	return z.wrap(bi)
}
func (z *Int) Lsh(x *Int, n uint) *Int {
	z.ensureInitialized()
	x.ensureInitialized()
	bi := new(big.Int).Lsh(x.Big(), n)
	return z.wrap(bi)
}
func (z *Int) Rsh(x *Int, n uint) *Int {
	z.ensureInitialized()
	x.ensureInitialized()
	bi := new(big.Int).Rsh(x.Big(), n)
	return z.wrap(bi)
}
func (z *Int) Xor(x *Int, y *Int) *Int {
	z.ensureInitialized()
	x.ensureInitialized()
	y.ensureInitialized()
	bi := new(big.Int).Xor(x.Big(), y.Big())
	return z.wrap(bi)
}
func (z *Int) GCD(x, y, a, b *Int) *Int {
	z.ensureInitialized()
	a.ensureInitialized()
	b.ensureInitialized()
	var bi *big.Int
	if x == nil && y == nil {
		bi = z.Big().GCD(nil, nil, a.Big(), b.Big())
	} else {
		x.ensureInitialized()
		y.ensureInitialized()
		bi = z.Big().GCD(x.Big(), y.Big(), a.Big(), b.Big())
	}
	return z.wrap(bi)
}
func (z *Int) ProbablyPrime(n int) bool {
	z.ensureInitialized()
	return z.Big().ProbablyPrime(n)
}
func (z *Int) And(x, y *Int) *Int {
	z.ensureInitialized()
	x.ensureInitialized()
	y.ensureInitialized()
	bi := new(big.Int).And(x.Big(), y.Big())
	return z.wrap(bi)
}

// getters
func (z *Int) Sign() int {
	z.ensureInitialized()
	return z.Big().Sign()
}
func (z *Int) Int64() int64 {
	z.ensureInitialized()
	return z.Big().Int64()
}
func (z *Int) Uint64() uint64 {
	z.ensureInitialized()
	return z.Big().Uint64()
}
func (z *Int) Bit(i int) uint {
	z.ensureInitialized()
	return z.Big().Bit(i)
}
func (z *Int) Bytes() []byte {
	z.ensureInitialized()
	return z.Big().Bytes()
}
func (z *Int) Big() *big.Int {
	z.ensureInitialized()
	if constantTimeIntEnabled {
		return z.i.Big()
	} else {
		return z.i2
	}
}

// -----

func (z *Int) ensureInitialized() {
	if constantTimeIntEnabled && z.i == nil {
		z.i = new(big_const.Int)
	} else if !constantTimeIntEnabled && z.i2 == nil {
		z.i2 = new(big.Int)
	}
	if z.mutex == nil {
		z.mutex = new(sync.RWMutex)
	}
}
func (z *Int) wrap(bi *big.Int) *Int {
	wrapped := Wrap(bi)
	z.i = wrapped.i
	z.i2 = wrapped.i2
	return z
}

func SetString(s string, base int) (*Int, bool) {
	bi := new(big.Int)
	var b bool
	bi, b = bi.SetString(s, base)
	return Wrap(bi), b
}

func (z *Int) MarshalJSON() ([]byte, error) {
	return json.Marshal(z.Big())
}

func (z *Int) UnmarshalJSON(b []byte) error {
	var Z big.Int
	if err := json.Unmarshal(b, &Z); err != nil {
		return err
	}
	z_ := Wrap(&Z)
	*z = *z_
	return nil
}

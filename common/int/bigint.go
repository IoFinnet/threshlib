// Constant time big.Int (best effort)

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
		mutex sync.RWMutex
	}
)

func NewInt(x uint64) *Int {
	return &Int{new(big_const.Int).SetUint64(x), sync.RWMutex{}}
}

func Wrap(i *big.Int) *Int {
	cBI := new(big_const.Int).SetBytes(i.Bytes())
	if i.Cmp(zero.Big()) < 0 {
		cBI = cBI.Neg(1)
	}
	return &Int{cBI, sync.RWMutex{}}
}

func (z *Int) Set(x *Int) *Int {
	z.ensureInitialized()
	x.ensureInitialized()
	z.mutex.Lock()
	defer z.mutex.Unlock()
	z.i = z.i.SetBytes(x.Bytes())
	return z
}
func (z *Int) SetBytes(data []byte) *Int {
	z.ensureInitialized()
	z.mutex.Lock()
	defer z.mutex.Unlock()
	z.i = z.i.SetBytes(data)
	return z
}
func (z *Int) SetInt64(x int64) *Int {
	if x < 0 {
		panic("SetInt64 used with a negative int64")
	}
	z.ensureInitialized()
	z.mutex.Lock()
	defer z.mutex.Unlock()
	z.i = z.i.SetUint64(uint64(x))
	return z
}
func (z *Int) SetUint64(x uint64) *Int {
	z.ensureInitialized()
	z.mutex.Lock()
	defer z.mutex.Unlock()
	z.i = z.i.SetUint64(x)
	return z
}
func (z *Int) SetNat(x *big_const.Nat) *Int {
	z.ensureInitialized()
	z.mutex.Lock()
	defer z.mutex.Unlock()
	z.i = z.i.SetNat(x)
	return z
}
func (z *Int) SetBig(x *big.Int, size int) *Int {
	z.ensureInitialized()
	z.mutex.Lock()
	defer z.mutex.Unlock()
	z.i = z.i.SetBig(x, size)
	return z
}
func (z *Int) Clone() *Int {
	z.ensureInitialized()
	z.mutex.Lock()
	defer z.mutex.Unlock()
	cloned := new(Int)
	cloned.i = z.i.Clone()
	return cloned
}
func (z *Int) Resize(cap int) *Int {
	z.ensureInitialized()
	z.mutex.Lock()
	defer z.mutex.Unlock()
	z.i = z.i.Resize(cap)
	return z
}
func (z *Int) Eq(x *Int) big_const.Choice {
	z.ensureInitialized()
	x.ensureInitialized()
	return z.i.Eq(x.i)
}
func (z *Int) Cmp(y *Int) (r int) {
	z.ensureInitialized()
	y.ensureInitialized()
	return z.i.Big().Cmp(y.i.Big())
}
func (z *Int) Abs() *big_const.Nat {
	z.ensureInitialized()
	z.mutex.RLock()
	defer z.mutex.RUnlock()
	return z.i.Abs()
}
func (z *Int) IsNegative() big_const.Choice {
	z.ensureInitialized()
	return z.IsNegative()
}
func (z *Int) AnnouncedLen() int {
	z.ensureInitialized()
	z.mutex.RLock()
	defer z.mutex.RUnlock()
	return z.i.AnnouncedLen()
}
func (z *Int) BitLen() int {
	z.ensureInitialized()
	z.mutex.RLock()
	defer z.mutex.RUnlock()
	// TODO: this leaks the value, but AnnouncedLen will not work for generating primes.
	return z.i.TrueLen()
}
func (z *Int) Neg(x *Int) *Int {
	z.ensureInitialized()
	x.ensureInitialized()
	z.mutex.Lock()
	defer z.mutex.Unlock()
	// allocate a new *Int otherwise we will mutate arg `x`
	z.i = x.Clone().i.Neg(1)
	return z
}
func (z *Int) SetNeg() *Int {
	z.ensureInitialized()
	z.mutex.Lock()
	defer z.mutex.Unlock()
	z.i = z.i.Neg(1)
	return z
}
func (z *Int) SetInt(x *Int) *Int {
	z.ensureInitialized()
	x.ensureInitialized()
	z.mutex.Lock()
	defer z.mutex.Unlock()
	z.i = x.i
	return z
}
func (z *Int) Add(x, y *Int) *Int {
	z.ensureInitialized()
	x.ensureInitialized()
	y.ensureInitialized()
	z.mutex.Lock()
	defer z.mutex.Unlock()
	z.i = z.i.Add(x.i, y.i, -1)
	return z
}
func (z *Int) Mul(x, y *Int) *Int {
	z.ensureInitialized()
	x.ensureInitialized()
	y.ensureInitialized()
	z.mutex.Lock()
	defer z.mutex.Unlock()
	z.i = z.i.Clone().Mul(x.i.Clone(), y.i.Clone(), -1)
	return z
}
func (z *Int) Mod(x, y *Int) *Int {
	z.ensureInitialized()
	x.ensureInitialized()
	y.ensureInitialized()
	z.mutex.Lock()
	defer z.mutex.Unlock()
	z.i = z.i.SetBytes(x.i.Mod(big_const.ModulusFromBytes(y.Bytes())).Bytes())
	return z
}
func (z *Int) SetModSymmetric(x *big_const.Nat, m *big_const.Modulus) *Int {
	z.ensureInitialized()
	z.mutex.Lock()
	defer z.mutex.Unlock()
	z.i = z.i.SetModSymmetric(x, m)
	return z
}
func (z *Int) CheckInRange(m *big_const.Modulus) big_const.Choice {
	z.ensureInitialized()
	z.mutex.RLock()
	defer z.mutex.RUnlock()
	return z.i.CheckInRange(m)
}
func (z *Int) String() string {
	z.ensureInitialized()
	z.mutex.RLock()
	defer z.mutex.RUnlock()
	return z.i.String()
}

// TODO: DANGER ZONE! Revisit
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
	bi := new(big.Int).Sub(x.i.Big(), y.i.Big())
	return z.wrap(bi)
}
func (z *Int) Div(x, y *Int) *Int {
	z.ensureInitialized()
	x.ensureInitialized()
	y.ensureInitialized()
	bi := new(big.Int).Div(x.i.Big(), y.i.Big())
	return z.wrap(bi)
}
func (z *Int) Exp(x, y, m *Int) *Int {
	z.ensureInitialized()
	x.ensureInitialized()
	y.ensureInitialized()
	m.ensureInitialized()
	var bi *big.Int
	if m == nil {
		bi = new(big.Int).Exp(x.i.Big(), y.i.Big(), nil)
	} else {
		bi = new(big.Int).Exp(x.i.Big(), y.i.Big(), m.i.Big())
	}
	return z.wrap(bi)
}
func (z *Int) ModInverse(x, m *Int) *Int {
	z.ensureInitialized()
	x.ensureInitialized()
	m.ensureInitialized()
	bi := new(big.Int).ModInverse(x.i.Big(), m.i.Big())
	return z.wrap(bi)
}
func (z *Int) Sqrt(x *Int) *Int {
	z.ensureInitialized()
	x.ensureInitialized()
	bi := new(big.Int).Sqrt(x.i.Big())
	return z.wrap(bi)

}
func (z *Int) ModSqrt(x, m *Int) *Int {
	z.ensureInitialized()
	x.ensureInitialized()
	m.ensureInitialized()
	bi := new(big.Int).ModSqrt(x.i.Big(), m.i.Big())
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
		bi = z.i.Big().GCD(nil, nil, a.Big(), b.Big())
	} else {
		x.ensureInitialized()
		y.ensureInitialized()
		bi = z.i.Big().GCD(x.Big(), y.Big(), a.Big(), b.Big())
	}
	return z.wrap(bi)
}
func (z *Int) ProbablyPrime(n int) bool {
	z.ensureInitialized()
	return z.i.Big().ProbablyPrime(n)
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
	return z.i.Big().Sign()
}
func (z *Int) Int64() int64 {
	z.ensureInitialized()
	return z.i.Big().Int64()
}
func (z *Int) Uint64() uint64 {
	z.ensureInitialized()
	return z.i.Big().Uint64()
}
func (z *Int) Bit(i int) uint {
	z.ensureInitialized()
	return z.i.Big().Bit(i)
}
func (z *Int) Bytes() []byte {
	z.ensureInitialized()
	return z.i.Big().Bytes()
}
func (z *Int) Big() *big.Int {
	z.ensureInitialized()
	return z.i.Big()
}

// -----

func (z *Int) ensureInitialized() {
	if z.i == nil {
		z.i = new(big_const.Int)
	}
}
func (z *Int) wrap(bi *big.Int) *Int {
	wrapped := Wrap(bi)
	z.i = wrapped.i
	return z
}

func (z *Int) Text(base int) string {
	z.ensureInitialized()
	z.mutex.RLock()
	defer z.mutex.RUnlock()
	return z.i.Big().Text(base)
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

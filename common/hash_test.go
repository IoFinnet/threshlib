package common_test

import (
	"testing"

	. "github.com/binance-chain/tss-lib/common"
	big "github.com/binance-chain/tss-lib/common/int"
	"github.com/stretchr/testify/assert"
)

func TestSHA512_256(t *testing.T) {
	input := [][]byte{[]byte("abc"), []byte("def"), []byte("ghi")}
	input2 := [][]byte{[]byte("abc"), []byte("def"), []byte("gh")}
	type args struct {
		in [][]byte
	}
	tests := []struct {
		name     string
		args     args
		want     []byte
		wantDiff bool
		wantLen  int
	}{{
		name:    "same inputs produce the same hash",
		args:    args{input},
		want:    SHA512_256(input...),
		wantLen: 256 / 8,
	}, {
		name:     "different inputs produce a differing hash",
		args:     args{input2},
		want:     SHA512_256(input...),
		wantDiff: true,
		wantLen:  256 / 8,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SHA512_256(tt.args.in...)
			if tt.wantDiff {
				if !assert.NotEqualf(t, tt.want, got, "SHA512_256(%v)", tt.args.in) {
					t.Errorf("SHA512_256() = %v, do not want %v", got, tt.want)
				}
			} else {
				if !assert.Equalf(t, tt.want, got, "SHA512_256(%v)", tt.args.in) {
					t.Errorf("SHA512_256() = %v, want %v", got, tt.want)
				}
			}
			if tt.wantLen != len(got) {
				t.Errorf("SHA512_256() = bitlen %d, want %d", len(got), tt.wantLen)
			}
		})
	}
}

func TestSHA512_256i(t *testing.T) {
	input := ByteSlicesToBigInts([][]byte{[]byte("abc"), []byte("def"), []byte("ghi")})
	input2 := ByteSlicesToBigInts([][]byte{[]byte("abc"), []byte("def"), []byte("gh")})
	input3 := new(big.Int).SetBytes([]byte("abc"))
	t.Logf("%d", input3.Int64())
	t.Logf("%d", new(big.Int).Neg(input3).Int64())
	type args struct {
		in []*big.Int
	}
	tests := []struct {
		name     string
		args     args
		want     *big.Int
		wantDiff bool
	}{{
		name: "same inputs produce the same hash",
		args: args{input},
		want: SHA512_256i(input...),
	}, {
		name:     "different inputs produce a differing hash",
		args:     args{input2},
		want:     SHA512_256i(input...),
		wantDiff: true,
	}, {
		name:     "different inputs produce a differing hash: Hash(-a) != Hash(a)",
		args:     args{[]*big.Int{new(big.Int).Neg(input3)}},
		want:     SHA512_256i(input3),
		wantDiff: true,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SHA512_256i(tt.args.in...)
			if tt.wantDiff {
				if !assert.NotEqualf(t, tt.want, got, "SHA512_256i(%v)", tt.args.in) {
					t.Errorf("SHA512_256i() = %v, do not want %v", got, tt.want)
				}
			} else {
				if !assert.Equalf(t, tt.want, got, "SHA512_256i(%v)", tt.args.in) {
					t.Errorf("SHA512_256i() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestSHA512_256iOne(t *testing.T) {
	input := new(big.Int).SetBytes([]byte("abc"))
	input2 := new(big.Int).SetBytes([]byte("ab"))
	input3 := new(big.Int).SetBytes([]byte("cd"))
	type args struct {
		in *big.Int
	}
	tests := []struct {
		name     string
		args     args
		want     *big.Int
		wantDiff bool
	}{{
		name: "same inputs produce the same hash",
		args: args{input},
		want: SHA512_256iOne(input),
	}, {
		name:     "different inputs produce a differing hash",
		args:     args{input2},
		want:     SHA512_256iOne(input),
		wantDiff: true,
	}, {
		name:     "different inputs produce a differing hash: Hash(-a) != Hash(a)",
		args:     args{new(big.Int).Neg(input3)},
		want:     SHA512_256i(input3),
		wantDiff: true,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SHA512_256iOne(tt.args.in)
			if tt.wantDiff {
				if !assert.NotEqualf(t, tt.want, got, "SHA512_256iOne(%v)", tt.args.in) {
					t.Errorf("SHA512_256iOne() = %v, do not want %v", got, tt.want)
				}
			} else {
				if !assert.Equalf(t, tt.want, got, "SHA512_256iOne(%v)", tt.args.in) {
					t.Errorf("SHA512_256iOne() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

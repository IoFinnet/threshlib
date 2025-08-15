package paillier

import (
	"math/big"
	"testing"
)

// TestValidateModulusStructure tests the enhanced validation to prevent small factor attacks
func TestValidateModulusStructure(t *testing.T) {
	tests := []struct {
		name     string
		modulus  func() *big.Int
		expected bool
	}{
		{
			name: "Valid 2048-bit RSA modulus",
			modulus: func() *big.Int {
				// Valid 2048-bit RSA modulus (product of two 1024-bit primes)
				p := new(big.Int)
				p.SetString("149996172127603611798988400909274085321780017265280298802435056378338737070932426692234360344106645625603780222488850584727288088069573194992315563897999986057169380072492189910614056128284917129010358964941671730314241857987040639562359039310286035855307141806554493968398140520439046054734613488672218899127", 10)
				q := new(big.Int)
				q.SetString("151973670375032632902296401845549110612016286052685442417331747700007272902079831784952319955981135634357590070001919772279704658019929617746807475159398917344451523575830819339976293039331844070299309624005258408090409161570866554320933924076176289632740458527585450196901262122004352329047166749875390428639", 10)
				return new(big.Int).Mul(p, q)
			},
			expected: true,
		},
		{
			name: "Modulus with small factor 997 (below 1000)",
			modulus: func() *big.Int {
				// N = 997 * large_prime^2
				smallFactor := big.NewInt(997)
				p := new(big.Int)
				p.SetString("10058746460281643652062381438198757978736258992982143244545126314862763623900996753709990754861589417420082999094566180944922146770293432952191910187419046676112551101152950238535561081635628134435941468921394532320423137913510778334795346919168868621004066330120618680508734521597181674130176264754451", 10)
				temp := new(big.Int).Mul(smallFactor, p)
				return new(big.Int).Mul(temp, p)
			},
			expected: false,
		},
		{
			name: "6ix1een attack: modulus with 16 factors > 1000",
			modulus: func() *big.Int {
				// Create N with 16 small primes all > 1000
				primes := []int64{1009, 1013, 1019, 1021, 1031, 1033, 1039, 1049,
					1051, 1061, 1063, 1069, 1087, 1091, 1093, 1097}
				result := big.NewInt(1)
				for _, p := range primes {
					result.Mul(result, big.NewInt(p))
				}
				// Multiply by a large prime to get sufficient bit length
				largePrime := new(big.Int)
				largePrime.SetString("170141183460469231731687303715884105727", 10) // 2^127 - 1 (Mersenne prime)
				result.Mul(result, largePrime)
				result.Mul(result, largePrime) // Square it to get enough bits
				return result
			},
			expected: false,
		},
		{
			name: "Modulus with factor 1009 (just above 1000)",
			modulus: func() *big.Int {
				// N = 1009 * large_prime^2
				smallFactor := big.NewInt(1009)
				p := new(big.Int)
				p.SetString("10058746460281643652062381438198757978736258992982143244545126314862763623900996753709990754861589417420082999094566180944922146770293432952191910187419046676112551101152950238535561081635628134435941468921394532320423137913510778334795346919168868621004066330120618680508734521597181674130176264754451", 10)
				temp := new(big.Int).Mul(smallFactor, p)
				return new(big.Int).Mul(temp, p)
			},
			expected: false,
		},
		{
			name: "Too small modulus (1024 bits)",
			modulus: func() *big.Int {
				// A 1024-bit modulus (too small)
				p := new(big.Int)
				p.SetString("179769313486231590770839156793787453197860296048756011706444423684197180216158519368947833795864925541502180565485980503646440548199239100050792877003355816639229553136239076508735759914822574862575007425302077447712589550957937778424442426617334727629299387668709205606050270810842907692932019128194467627007", 10)
				return p
			},
			expected: false,
		},
		{
			name: "Even modulus",
			modulus: func() *big.Int {
				p := new(big.Int)
				p.SetString("32317006071311007300338913926423828248817941241140239112842009751400741706634354222619689417363569347117901737909704191754605873209195028853758986185622153212175412514901774520270235952464142731030324970880982788015341561182668577421321476322568618679651684868296477363215457073126073200318026220593503490803", 10)
				q := new(big.Int)
				q.SetString("31265656041032373263895246387231549771234696950543851936050436778383725833370896962208043092016088100407155119470512645459077363050026391833351569019640432858869912635176480311773489934167613158154884193709775876541711779746423110548124038051937114038090494309377208104871350077313816681725577873024331895293", 10)
				n := new(big.Int).Mul(p, q)
				// Make it even
				return new(big.Int).Mul(n, big.NewInt(2))
			},
			expected: false,
		},
		{
			name: "Perfect square",
			modulus: func() *big.Int {
				p := new(big.Int)
				p.SetString("32317006071311007300338913926423828248817941241140239112842009751400741706634354222619689417363569347117901737909704191754605873209195028853758986185622153212175412514901774520270235952464142731030324970880982788015341561182668577421321476322568618679651684868296477363215457073126073200318026220593503490803", 10)
				// N = p^2 (perfect square)
				return new(big.Int).Mul(p, p)
			},
			expected: false,
		},
		{
			name: "Prime modulus (not composite)",
			modulus: func() *big.Int {
				// A large prime (not a product)
				p := new(big.Int)
				p.SetString("32317006071311007300338913926423828248817941241140239112842009751400741706634354222619689417363569347117901737909704191754605873209195028853758986185622153212175412514901774520270235952464142731030324970880982788015341561182668577421321476322568618679651684868296477363215457073126073200318026220593503490803", 10)
				return p
			},
			expected: false,
		},
		{
			name: "Modulus with factor 65521 (near upper limit)",
			modulus: func() *big.Int {
				// N = 65521 * large_prime * large_prime  (65521 is prime and < 65536)
				smallFactor := big.NewInt(65521)
				p := new(big.Int)
				p.SetString("32317006071311007300338913926423828248817941241140239112842009751400741706634354222619689417363569347117901737909704191754605873209195028853758986185622153212175412514901774520270235952464142731030324970880982788015341561182668577421321476322568618679651684868296477363215457073126073200318026220593503490803", 10)
				temp := new(big.Int).Mul(smallFactor, p)
				return new(big.Int).Mul(temp, p)
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			N := tt.modulus()
			result := validateModulusStructure(N)
			if result != tt.expected {
				t.Errorf("validateModulusStructure() = %v, want %v for modulus with %d bits",
					result, tt.expected, N.BitLen())
			}
		})
	}
}

// TestPrevent6ix1eenAttack specifically tests protection against the 6ix1een attack
func TestPrevent6ix1eenAttack(t *testing.T) {
	// Create various malformed moduli that would enable the 6ix1een attack

	// Test 1: 16 small primes between 1000 and 2000
	primes1000to2000 := []int64{
		1009, 1013, 1019, 1021, 1031, 1033, 1039, 1049,
		1051, 1061, 1063, 1069, 1087, 1091, 1093, 1097,
	}

	n1 := big.NewInt(1)
	for _, p := range primes1000to2000 {
		n1.Mul(n1, big.NewInt(p))
	}
	// Add large factors to reach 2048 bits
	largeFactor := new(big.Int)
	largeFactor.SetString("170141183460469231731687303715884105727", 10)
	for n1.BitLen() < 2048 {
		n1.Mul(n1, largeFactor)
	}

	if validateModulusStructure(n1) {
		t.Error("Failed to detect 6ix1een attack with 16 primes between 1000-2000")
	}

	// Test 2: Mix of primes around 10000
	primes10000 := []int64{
		10007, 10009, 10037, 10039, 10061, 10067, 10069, 10079,
		10091, 10093, 10099, 10103, 10111, 10133, 10139, 10141,
	}

	n2 := big.NewInt(1)
	for _, p := range primes10000 {
		n2.Mul(n2, big.NewInt(p))
	}
	for n2.BitLen() < 2048 {
		n2.Mul(n2, largeFactor)
	}

	if validateModulusStructure(n2) {
		t.Error("Failed to detect 6ix1een attack with 16 primes around 10000")
	}

	// Test 3: Primes near the upper limit (close to 65536)
	primesNear65536 := []int64{
		65521, 65519, 65497, 65479, 65449, 65447, 65437, 65423,
		65419, 65413, 65407, 65393, 65381, 65371, 65369, 65357,
	}

	n3 := big.NewInt(1)
	for _, p := range primesNear65536 {
		n3.Mul(n3, big.NewInt(p))
	}
	for n3.BitLen() < 2048 {
		n3.Mul(n3, largeFactor)
	}

	if validateModulusStructure(n3) {
		t.Error("Failed to detect 6ix1een attack with 16 primes near 65536")
	}
}

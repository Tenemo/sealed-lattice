package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/bits"
	"os"

	"github.com/tuneinsight/lattigo/v6/ring"
)

// BGV RNS parameters (N=32768) that must byte-mirror the Rust/WASM kernel.
// This Go oracle exists only to cross-check ring/NTT arithmetic parity; pinnedCommit
// pins the Lattigo revision the parity check was validated against.
const polynomialDegree = 32768
const pinnedCommit = "5dbffbdea05394de2ca3a432ed5318aa832e3f40"
const canonicalMaterialFixturePath = "sealed-lattice-canonical-rns-fixtures.json"

// 17-entry data+special prime basis (~2^47 NTT-friendly primes) of the BGV RNS parameters.
var selectedModuli = []uint64{
	140737487306753,
	140737486716929,
	140737486520321,
	140737485864961,
	140737484685313,
	140737483898881,
	140737482981377,
	140737481801729,
	140737481342977,
	140737480949761,
	140737480359937,
	140737479639041,
	140737476100097,
	140737472299009,
	140737471971329,
	140737471774721,
	140737471578113,
}

type sample struct {
	Position int    `json:"position"`
	Value    uint64 `json:"value"`
}

type canonicalRnsFixture struct {
	SchemaVersion                int      `json:"schemaVersion"`
	FixtureID                    string   `json:"fixtureId"`
	Source                       string   `json:"source"`
	PolynomialDegree             int      `json:"polynomialDegree"`
	Moduli                       []uint64 `json:"moduli"`
	SamplePositions              []int    `json:"samplePositions"`
	LeftCoefficientFormula       string   `json:"leftCoefficientFormula"`
	RightCoefficientFormula      string   `json:"rightCoefficientFormula"`
	ReferenceSerializationPolicy string   `json:"referenceSerializationPolicy"`
	ProtocolEvidence             bool     `json:"protocolEvidence"`
}

type oracleReport struct {
	ArtifactKind                         string   `json:"artifactKind"`
	PinnedCommit                         string   `json:"pinnedCommit"`
	PolynomialDegree                     int      `json:"polynomialDegree"`
	Moduli                               []uint64 `json:"moduli"`
	ComparableOperations                 []string `json:"comparableOperations"`
	ConventionDifferences                []string `json:"conventionDifferences"`
	RoundTripMatched                     bool     `json:"roundTripMatched"`
	AdditionMatched                      bool     `json:"additionMatched"`
	SubtractionMatched                   bool     `json:"subtractionMatched"`
	MultiplicationMatched                bool     `json:"multiplicationMatched"`
	SealedLatticeCanonicalMaterialUsed   bool     `json:"sealedLatticeCanonicalMaterialUsed"`
	CanonicalMaterialFixtureID           string   `json:"canonicalMaterialFixtureId"`
	CanonicalMaterialFixtureHash       string   `json:"canonicalMaterialFixtureHash"`
	CanonicalMaterialSerializationPolicy string   `json:"canonicalMaterialSerializationPolicy"`
	ReferenceSerializationUsed           bool     `json:"referenceSerializationUsed"`
	ProtocolEvidence                     bool     `json:"protocolEvidence"`
	InputHash                          string   `json:"inputHash"`
	RoundTripSamples                     []sample `json:"roundTripSamples"`
	AdditionSamples                      []sample `json:"additionSamples"`
}

func main() {
	report, err := buildReport()
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

func buildReport() (oracleReport, error) {
	fixture, fixtureHash, err := loadCanonicalFixture()
	if err != nil {
		return oracleReport{}, err
	}
	referenceRing, err := ring.NewRing(polynomialDegree, selectedModuli)
	if err != nil {
		return oracleReport{}, fmt.Errorf("create Lattigo ring: %w", err)
	}
	left := ring.NewPoly(polynomialDegree, len(selectedModuli)-1)
	right := ring.NewPoly(polynomialDegree, len(selectedModuli)-1)
	for modulusIndex, modulus := range fixture.Moduli {
		for coefficientIndex := 0; coefficientIndex < polynomialDegree; coefficientIndex++ {
			left.Coeffs[modulusIndex][coefficientIndex] = patternValue(coefficientIndex, modulus)
			// +17 offset just decorrelates the two operands; not a protocol constant.
			right.Coeffs[modulusIndex][coefficientIndex] = patternValue(coefficientIndex+17, modulus)
		}
	}

	transformed := ring.NewPoly(polynomialDegree, len(selectedModuli)-1)
	recovered := ring.NewPoly(polynomialDegree, len(selectedModuli)-1)
	referenceRing.NTT(left, transformed)
	referenceRing.INTT(transformed, recovered)
	roundTripMatched := referenceRing.Equal(left, recovered)

	addition := ring.NewPoly(polynomialDegree, len(selectedModuli)-1)
	referenceRing.Add(left, right, addition)
	additionMatched := true
	subtraction := ring.NewPoly(polynomialDegree, len(selectedModuli)-1)
	referenceRing.Sub(left, right, subtraction)
	subtractionMatched := true
	multiplication := ring.NewPoly(polynomialDegree, len(selectedModuli)-1)
	referenceRing.MulCoeffsBarrett(left, right, multiplication)
	multiplicationMatched := true
	for modulusIndex, modulus := range selectedModuli {
		for coefficientIndex := 0; coefficientIndex < polynomialDegree; coefficientIndex++ {
			expected := (left.Coeffs[modulusIndex][coefficientIndex] + right.Coeffs[modulusIndex][coefficientIndex]) % modulus
			if addition.Coeffs[modulusIndex][coefficientIndex] != expected {
				additionMatched = false
				break
			}
			expected = (left.Coeffs[modulusIndex][coefficientIndex] + modulus - right.Coeffs[modulusIndex][coefficientIndex]) % modulus
			if subtraction.Coeffs[modulusIndex][coefficientIndex] != expected {
				subtractionMatched = false
				break
			}
			expected = mulModExpected(left.Coeffs[modulusIndex][coefficientIndex], right.Coeffs[modulusIndex][coefficientIndex], modulus)
			if multiplication.Coeffs[modulusIndex][coefficientIndex] != expected {
				multiplicationMatched = false
				break
			}
		}
	}

	return oracleReport{
		ArtifactKind:                         "lattigo-development-oracle-vector",
		PinnedCommit:                         pinnedCommit,
		PolynomialDegree:                     polynomialDegree,
		Moduli:                               selectedModuli,
		ComparableOperations:                 []string{"ring.NewRing", "NTTThenINTTRoundTrip", "CoefficientAddition", "CoefficientSubtraction", "CoefficientMultiplicationBarrett"},
		ConventionDifferences:                []string{"coefficient-ordering-reviewed", "ntt-root-direction-reviewed", "automorphism-direction-not-used", "slot-ordering-not-accepted-as-protocol-evidence", "plaintext-encoding-convention-not-accepted-as-protocol-evidence", "key-switch-decomposition-not-covered", "ciphertext-component-order-not-covered"},
		RoundTripMatched:                     roundTripMatched,
		AdditionMatched:                      additionMatched,
		SubtractionMatched:                   subtractionMatched,
		MultiplicationMatched:                multiplicationMatched,
		SealedLatticeCanonicalMaterialUsed:   true,
		CanonicalMaterialFixtureID:           fixture.FixtureID,
		CanonicalMaterialFixtureHash:       fixtureHash,
		CanonicalMaterialSerializationPolicy: fixture.ReferenceSerializationPolicy,
		ReferenceSerializationUsed:           false,
		ProtocolEvidence:                     false,
		InputHash:                          hashInputs(left),
		RoundTripSamples:                     samples(recovered.Coeffs[0], fixture.SamplePositions),
		AdditionSamples:                      samples(addition.Coeffs[0], fixture.SamplePositions),
	}, nil
}

func loadCanonicalFixture() (canonicalRnsFixture, string, error) {
	source, err := os.ReadFile(canonicalMaterialFixturePath)
	if err != nil {
		return canonicalRnsFixture{}, "", fmt.Errorf("read sealed-lattice canonical material fixture: %w", err)
	}
	hash := sha256.Sum256(source)

	var fixture canonicalRnsFixture
	if err := json.Unmarshal(source, &fixture); err != nil {
		return canonicalRnsFixture{}, "", fmt.Errorf("parse sealed-lattice canonical material fixture: %w", err)
	}
	if err := validateCanonicalFixture(fixture); err != nil {
		return canonicalRnsFixture{}, "", err
	}

	return fixture, hex.EncodeToString(hash[:]), nil
}

func validateCanonicalFixture(fixture canonicalRnsFixture) error {
	if fixture.SchemaVersion != 1 {
		return fmt.Errorf("sealed-lattice canonical material fixture schema version is %d, expected 1", fixture.SchemaVersion)
	}
	if fixture.Source != "sealed-lattice-rust-wasm-canonical-rns-fixture" {
		return fmt.Errorf(
			"sealed-lattice canonical material fixture source is %q, expected %q",
			fixture.Source,
			"sealed-lattice-rust-wasm-canonical-rns-fixture",
		)
	}
	if fixture.PolynomialDegree != polynomialDegree {
		return fmt.Errorf("sealed-lattice canonical material fixture polynomial degree is %d, expected %d", fixture.PolynomialDegree, polynomialDegree)
	}
	if len(fixture.Moduli) != len(selectedModuli) {
		return fmt.Errorf("sealed-lattice canonical material fixture modulus count is %d, expected %d", len(fixture.Moduli), len(selectedModuli))
	}
	for modulusIndex, modulus := range selectedModuli {
		if fixture.Moduli[modulusIndex] != modulus {
			return fmt.Errorf("sealed-lattice canonical material fixture modulus %d is %d, expected %d", modulusIndex, fixture.Moduli[modulusIndex], modulus)
		}
	}
	if fixture.ProtocolEvidence {
		return fmt.Errorf("sealed-lattice canonical material fixture must not claim protocol evidence")
	}
	if fixture.ReferenceSerializationPolicy != "sealed-lattice-canonical-material-only-lattigo-serialization-rejected" {
		return fmt.Errorf("sealed-lattice canonical material fixture has unexpected serialization policy %q", fixture.ReferenceSerializationPolicy)
	}

	// Fixed coefficient indices the Rust side also samples, for cross-impl comparison.
	expectedSamplePositions := []int{0, 1, 2, 17, polynomialDegree / 2, polynomialDegree - 1}
	if len(fixture.SamplePositions) != len(expectedSamplePositions) {
		return fmt.Errorf("sealed-lattice canonical material fixture sample position count is %d, expected %d", len(fixture.SamplePositions), len(expectedSamplePositions))
	}
	for index, position := range expectedSamplePositions {
		if fixture.SamplePositions[index] != position {
			return fmt.Errorf("sealed-lattice canonical material fixture sample position %d is %d, expected %d", index, fixture.SamplePositions[index], position)
		}
	}

	return nil
}

// Arbitrary deterministic quadratic test pattern (pos^2 + 31*pos + 7); the specific
// coefficients carry no protocol meaning, they just produce reproducible inputs.
func patternValue(position int, modulus uint64) uint64 {
	value := uint64(position*position + 31*position + 7)
	return value % modulus
}

func mulModExpected(left, right, modulus uint64) uint64 {
	high, low := bits.Mul64(left, right)
	_, remainder := bits.Div64(high, low, modulus)
	return remainder
}

func samples(values []uint64, positions []int) []sample {
	output := make([]sample, 0, len(positions))
	for _, position := range positions {
		output = append(output, sample{
			Position: position,
			Value:    values[position],
		})
	}
	return output
}

func hashInputs(poly ring.Poly) string {
	hasher := sha256.New()
	for _, limb := range poly.Coeffs {
		for _, value := range samples(limb, []int{0, 1, 2, 17, len(limb) / 2, len(limb) - 1}) {
			_, _ = fmt.Fprintf(hasher, "%d:%d;", value.Position, value.Value)
		}
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

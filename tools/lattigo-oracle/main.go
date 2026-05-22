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

const polynomialDegree = 32768
const pinnedCommit = "5dbffbdea05394de2ca3a432ed5318aa832e3f40"

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

type oracleReport struct {
	ArtifactKind               string   `json:"artifactKind"`
	PinnedCommit               string   `json:"pinnedCommit"`
	PolynomialDegree           int      `json:"polynomialDegree"`
	Moduli                     []uint64 `json:"moduli"`
	ComparableOperations       []string `json:"comparableOperations"`
	ConventionDifferences      []string `json:"conventionDifferences"`
	RoundTripMatched           bool     `json:"roundTripMatched"`
	AdditionMatched            bool     `json:"additionMatched"`
	SubtractionMatched         bool     `json:"subtractionMatched"`
	MultiplicationMatched      bool     `json:"multiplicationMatched"`
	ReferenceSerializationUsed bool     `json:"referenceSerializationUsed"`
	ProtocolEvidence           bool     `json:"protocolEvidence"`
	InputDigest                string   `json:"inputDigest"`
	RoundTripSamples           []sample `json:"roundTripSamples"`
	AdditionSamples            []sample `json:"additionSamples"`
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
	referenceRing, err := ring.NewRing(polynomialDegree, selectedModuli)
	if err != nil {
		return oracleReport{}, fmt.Errorf("create Lattigo ring: %w", err)
	}
	left := ring.NewPoly(polynomialDegree, len(selectedModuli)-1)
	right := ring.NewPoly(polynomialDegree, len(selectedModuli)-1)
	for modulusIndex, modulus := range selectedModuli {
		for coefficientIndex := 0; coefficientIndex < polynomialDegree; coefficientIndex++ {
			left.Coeffs[modulusIndex][coefficientIndex] = patternValue(coefficientIndex, modulus)
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
		ArtifactKind:               "lattigo-development-oracle-vector",
		PinnedCommit:               pinnedCommit,
		PolynomialDegree:           polynomialDegree,
		Moduli:                     selectedModuli,
		ComparableOperations:       []string{"ring.NewRing", "NTTThenINTTRoundTrip", "CoefficientAddition", "CoefficientSubtraction", "CoefficientMultiplicationBarrett"},
		ConventionDifferences:      []string{"coefficient-ordering-reviewed", "ntt-root-direction-reviewed", "automorphism-direction-not-used", "slot-ordering-not-accepted-as-protocol-evidence", "plaintext-encoding-convention-not-accepted-as-protocol-evidence", "key-switch-decomposition-not-covered", "ciphertext-component-order-not-covered"},
		RoundTripMatched:           roundTripMatched,
		AdditionMatched:            additionMatched,
		SubtractionMatched:         subtractionMatched,
		MultiplicationMatched:      multiplicationMatched,
		ReferenceSerializationUsed: false,
		ProtocolEvidence:           false,
		InputDigest:                digestInputs(left),
		RoundTripSamples:           samples(recovered.Coeffs[0]),
		AdditionSamples:            samples(addition.Coeffs[0]),
	}, nil
}

func patternValue(position int, modulus uint64) uint64 {
	value := uint64(position*position + 31*position + 7)
	return value % modulus
}

func mulModExpected(left, right, modulus uint64) uint64 {
	high, low := bits.Mul64(left, right)
	_, remainder := bits.Div64(high, low, modulus)
	return remainder
}

func samples(values []uint64) []sample {
	positions := []int{0, 1, 2, 17, len(values) / 2, len(values) - 1}
	output := make([]sample, 0, len(positions))
	for _, position := range positions {
		output = append(output, sample{
			Position: position,
			Value:    values[position],
		})
	}
	return output
}

func digestInputs(poly ring.Poly) string {
	hasher := sha256.New()
	for _, limb := range poly.Coeffs {
		for _, value := range samples(limb) {
			_, _ = fmt.Fprintf(hasher, "%d:%d;", value.Position, value.Value)
		}
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

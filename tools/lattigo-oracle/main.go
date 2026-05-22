package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/tuneinsight/lattigo/v6/ring"
)

const polynomialDegree = 32768
const pinnedCommit = "5dbffbdea05394de2ca3a432ed5318aa832e3f40"

var selectedModuli = []uint64{
	140737487306753,
	140737486716929,
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
	RoundTripMatched           bool     `json:"roundTripMatched"`
	AdditionMatched            bool     `json:"additionMatched"`
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
	for modulusIndex, modulus := range selectedModuli {
		for coefficientIndex := 0; coefficientIndex < polynomialDegree; coefficientIndex++ {
			expected := (left.Coeffs[modulusIndex][coefficientIndex] + right.Coeffs[modulusIndex][coefficientIndex]) % modulus
			if addition.Coeffs[modulusIndex][coefficientIndex] != expected {
				additionMatched = false
				break
			}
		}
	}

	return oracleReport{
		ArtifactKind:               "lattigo-development-oracle-vector",
		PinnedCommit:               pinnedCommit,
		PolynomialDegree:           polynomialDegree,
		Moduli:                     selectedModuli,
		ComparableOperations:       []string{"ring.NewRing", "NTTThenINTTRoundTrip", "CoefficientAddition"},
		RoundTripMatched:           roundTripMatched,
		AdditionMatched:            additionMatched,
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

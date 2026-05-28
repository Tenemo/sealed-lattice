import { describe, expect, it } from 'vitest';

import ballotFieldLinearProofBackendVectorsJson from '#test-vectors/ballot-privacy/ballot-field-linear-proof-vectors.json';
import linearProofBackendVectorsJson from '#test-vectors/ballot-privacy/proof-backend-linear-vectors.json';
import receiverKeyLinearProofBackendVectorsJson from '#test-vectors/ballot-privacy/receiver-key-linear-proof-vectors.json';

type LinearProofBackendVectorCase = {
    readonly caseName: string;
    readonly expectedOutcome: string;
    readonly upstreamVectorAvailable: boolean;
    readonly proofEncoding?: {
        readonly profileId: string;
    };
    readonly proofHex: string | null;
    readonly publicRandomnessHex: string | null;
    readonly statementMatrixCoefficients?: readonly (readonly (readonly number[])[])[];
    readonly targetCoefficientRepresentation?:
        | 'canonicalUnsignedSourceModulus'
        | 'centeredSignedSourceModulus';
    readonly targetVectorCoefficients?: readonly (readonly number[])[];
    readonly trace?: {
        readonly expectedLogicalRejectionLayer?: string;
        readonly upstreamVerifierAccepted?: boolean;
        readonly sealedLatticePreflightTranscript?: {
            readonly domain: string;
            readonly hash: string;
            readonly parameterHash: string;
            readonly statementHash: string;
            readonly targetHash: string;
            readonly proofHash: string;
            readonly publicRandomnessHash: string;
            readonly preflightTranscriptHash: string;
        };
        readonly decodedProofFieldLengths?: {
            readonly fullProofBytes: number;
            readonly fields?: readonly {
                readonly name: string;
                readonly bitOffset: number;
                readonly bitLength: number;
                readonly byteStart: number;
                readonly byteEndExclusive: number;
            }[];
            readonly terminalPadding?: {
                readonly name: string;
                readonly bitOffset: number;
                readonly bitLength: number;
                readonly byteStart: number;
                readonly byteEndExclusive: number;
            };
            readonly decoderError?: string;
        };
    };
};

type LinearProofBackendVectorFile = {
    readonly generatedFromUpstreamLaZer: boolean;
    readonly generationStatus: string;
    readonly parameterSet: {
        readonly coefficientModulus: number;
    };
    readonly proofEncoding: {
        readonly profileId: string;
        readonly coefficientModulus?: number | string;
    };
    readonly provenance: {
        readonly upstreamRepositoryUrl: string;
        readonly upstreamCommitHash: string;
        readonly dockerfileSha256: string;
        readonly oracleDriverSha256?: string;
        readonly oracleRunnerSha256?: string;
        readonly receiverKeyParameterSourceSha256?: string;
        readonly vectorEmitterSha256: string;
        readonly profileWarning?: string;
        readonly licenseNote: string;
    };
    readonly requiredCaseNames: readonly string[];
    readonly targetCoefficientRepresentation?:
        | 'canonicalUnsignedSourceModulus'
        | 'centeredSignedSourceModulus';
    readonly cases: readonly LinearProofBackendVectorCase[];
};

type BallotFieldLinearProofVectorPatch = {
    readonly coefficient: number;
    readonly coefficientIndex: number;
    readonly columnIndex?: number;
    readonly rowIndex: number;
};

type BallotFieldLinearProofVectorCase = {
    readonly caseName: string;
    readonly description: string;
    readonly expectedOutcome: 'accept' | 'reject';
    readonly mutation: string;
    readonly proofHex?: string;
    readonly publicRandomnessHex?: string;
    readonly statementMatrixPatch?: BallotFieldLinearProofVectorPatch;
    readonly targetVectorPatch?: BallotFieldLinearProofVectorPatch;
    readonly trace: NonNullable<LinearProofBackendVectorCase['trace']>;
    readonly upstreamVectorAvailable: boolean;
};

type BallotFieldLinearProofVectorFile = {
    readonly generatedFromUpstreamLaZer: boolean;
    readonly generationStatus: string;
    readonly expectedProofSizeBytes: number;
    readonly linearStatement: {
        readonly coefficientModulus: string;
        readonly parameterProfileId: string;
        readonly projectionCoverage: string;
        readonly ringDegree: number;
        readonly statementColumns: number;
        readonly statementMatrixCoefficients: readonly (readonly (readonly number[])[])[];
        readonly statementRows: number;
        readonly targetVectorCoefficients: readonly (readonly number[])[];
        readonly witnessL2BoundSquared: string;
    };
    readonly parameterSet: {
        readonly coefficientModulus: number;
        readonly expectedProofSizeBytes: number;
        readonly profileId: string;
        readonly ringDegree: number;
        readonly statementColumns: number;
        readonly statementRows: number;
        readonly witnessL2BoundSquared: number;
    };
    readonly profileId: string;
    readonly proofEncoding: {
        readonly coefficientModulus: string;
        readonly compressedCoefficientBitLength: number;
        readonly fullSizeCoefficientBitLength: number;
        readonly profileId: string;
        readonly randomnessResponseVectorLength: number;
        readonly shortResponseVectorLength: number;
    };
    readonly proofHex: string;
    readonly projectionCoverage: string;
    readonly provenance: LinearProofBackendVectorFile['provenance'] & {
        readonly ballotFieldParameterSourceSha256: string;
        readonly generatedHeaderSha256: string;
        readonly oracleInputGeneratorSha256: string;
    };
    readonly publicRandomnessHex: string;
    readonly requiredCaseNames: readonly string[];
    readonly matrixCoefficientRepresentation: 'canonicalUnsignedSourceModulus';
    readonly targetCoefficientRepresentation: 'canonicalUnsignedSourceModulus';
    readonly cases: readonly BallotFieldLinearProofVectorCase[];
};

const linearProofBackendVectors =
    linearProofBackendVectorsJson as LinearProofBackendVectorFile;
const receiverKeyLinearProofBackendVectors =
    receiverKeyLinearProofBackendVectorsJson as LinearProofBackendVectorFile;
const ballotFieldLinearProofBackendVectors =
    ballotFieldLinearProofBackendVectorsJson as BallotFieldLinearProofVectorFile;
const forbiddenPublicVectorKeys = new Set([
    'privateWitness',
    'proofRandomness',
    'proverCoins',
    'receiverSecret',
    'secret',
    'witness',
]);
const lowercaseShake128HashPattern = /^[a-f0-9]{64}$/u;

const collectObjectKeys = (value: unknown, keys: Set<string>): void => {
    if (Array.isArray(value)) {
        for (const item of value) {
            collectObjectKeys(item, keys);
        }

        return;
    }
    if (value !== null && typeof value === 'object') {
        for (const [key, child] of Object.entries(value)) {
            keys.add(key);
            collectObjectKeys(child, keys);
        }
    }
};

describe('ballot privacy linear proof backend vectors', () => {
    it('records reproducible upstream oracle provenance for every required vector', () => {
        const caseNames = new Set(
            linearProofBackendVectors.cases.map(
                (vectorCase) => vectorCase.caseName,
            ),
        );

        expect(linearProofBackendVectors.generatedFromUpstreamLaZer).toBe(true);
        expect(linearProofBackendVectors.generationStatus).toBe('generated');
        expect(linearProofBackendVectors.targetCoefficientRepresentation).toBe(
            'centeredSignedSourceModulus',
        );
        expect(linearProofBackendVectors.provenance.upstreamRepositoryUrl).toBe(
            'https://github.com/lazer-crypto/lazer',
        );
        expect(linearProofBackendVectors.provenance.upstreamCommitHash).toMatch(
            /^[a-f0-9]{40}$/u,
        );
        expect(linearProofBackendVectors.provenance.dockerfileSha256).toMatch(
            /^[a-f0-9]{64}$/u,
        );
        expect(linearProofBackendVectors.provenance.oracleDriverSha256).toMatch(
            /^[a-f0-9]{64}$/u,
        );
        expect(linearProofBackendVectors.provenance.oracleRunnerSha256).toMatch(
            /^[a-f0-9]{64}$/u,
        );
        expect(
            linearProofBackendVectors.provenance.vectorEmitterSha256,
        ).toMatch(/^[a-f0-9]{64}$/u);
        expect(linearProofBackendVectors.provenance.licenseNote).toContain(
            'offline vector oracle',
        );
        for (const requiredCaseName of linearProofBackendVectors.requiredCaseNames) {
            expect(caseNames.has(requiredCaseName)).toBe(true);
        }
    });

    it('contains public-only generated proof bytes and canonical public statements', () => {
        const discoveredKeys = new Set<string>();
        collectObjectKeys(linearProofBackendVectors, discoveredKeys);
        for (const forbiddenKey of forbiddenPublicVectorKeys) {
            expect(discoveredKeys.has(forbiddenKey)).toBe(false);
        }

        for (const vectorCase of linearProofBackendVectors.cases) {
            expect(vectorCase.upstreamVectorAvailable).toBe(true);
            expect(vectorCase.expectedOutcome).toMatch(/^(accept|reject)$/u);
            expect(vectorCase.proofEncoding?.profileId).toBe(
                linearProofBackendVectors.proofEncoding.profileId,
            );
            expect(vectorCase.proofHex).toMatch(/^[a-f0-9]+$/u);
            expect(vectorCase.publicRandomnessHex).toMatch(/^[a-f0-9]{64}$/u);
            expect(vectorCase.statementMatrixCoefficients).toHaveLength(4);
            expect(vectorCase.targetVectorCoefficients).toHaveLength(4);
            expect(vectorCase.targetCoefficientRepresentation).toBe(
                'centeredSignedSourceModulus',
            );
        }
    });

    it('keeps trailing proof data as a sealed-lattice canonical decoder rejection', () => {
        const extendedProofCase = linearProofBackendVectors.cases.find(
            (vectorCase) => vectorCase.caseName === 'extended-proof',
        );

        expect(extendedProofCase).toBeDefined();
        expect(extendedProofCase?.expectedOutcome).toBe('reject');
        expect(extendedProofCase?.trace).toMatchObject({
            expectedLogicalRejectionLayer: 'proof-decoder',
            upstreamVerifierAccepted: true,
        });
        expect(
            extendedProofCase?.trace?.decodedProofFieldLengths?.decoderError,
        ).toBe('proof encoding contains trailing data');
    });

    it('records upstream rejection for proof, statement, target, randomness, and truncation mutations', () => {
        const expectedRejectedByUpstream = new Set([
            'mutated-statement-matrix',
            'mutated-target-vector',
            'mutated-proof-byte',
            'wrong-public-randomness',
            'truncated-proof',
        ]);

        for (const vectorCase of linearProofBackendVectors.cases) {
            if (expectedRejectedByUpstream.has(vectorCase.caseName)) {
                expect(vectorCase.trace).toMatchObject({
                    upstreamVerifierAccepted: false,
                });
            }
        }
    });

    it('records a sealed-lattice preflight transcript for public vector binding', () => {
        const validCase = linearProofBackendVectors.cases.find(
            (vectorCase) => vectorCase.caseName === 'valid-small-linear-proof',
        );
        const casesWithChangedPreflightHash = [
            'mutated-statement-matrix',
            'mutated-target-vector',
            'mutated-proof-byte',
            'wrong-public-randomness',
            'truncated-proof',
            'extended-proof',
        ];

        expect(
            validCase?.trace?.sealedLatticePreflightTranscript,
        ).toMatchObject({
            domain: 'sealed.vote/internal/linear-proof-preflight-v1',
            hash: 'SHAKE128-256',
        });
        const validPreflightTranscript =
            validCase?.trace?.sealedLatticePreflightTranscript;
        expect(validPreflightTranscript?.parameterHash).toMatch(
            lowercaseShake128HashPattern,
        );
        expect(validPreflightTranscript?.statementHash).toMatch(
            lowercaseShake128HashPattern,
        );
        expect(validPreflightTranscript?.targetHash).toMatch(
            lowercaseShake128HashPattern,
        );
        expect(validPreflightTranscript?.proofHash).toMatch(
            lowercaseShake128HashPattern,
        );
        expect(validPreflightTranscript?.publicRandomnessHash).toMatch(
            lowercaseShake128HashPattern,
        );
        expect(validPreflightTranscript?.preflightTranscriptHash).toMatch(
            lowercaseShake128HashPattern,
        );

        const validPreflightHash =
            validPreflightTranscript?.preflightTranscriptHash;
        expect(validPreflightHash).toBeDefined();
        for (const caseName of casesWithChangedPreflightHash) {
            const mutatedCase = linearProofBackendVectors.cases.find(
                (vectorCase) => vectorCase.caseName === caseName,
            );

            expect(
                mutatedCase?.trace?.sealedLatticePreflightTranscript
                    ?.preflightTranscriptHash,
            ).toMatch(lowercaseShake128HashPattern);
            expect(
                mutatedCase?.trace?.sealedLatticePreflightTranscript
                    ?.preflightTranscriptHash,
            ).not.toBe(validPreflightHash);
        }
    });

    it('keeps noncanonical coefficient encoding as a sealed-lattice decoder rejection', () => {
        const noncanonicalCase = linearProofBackendVectors.cases.find(
            (vectorCase) =>
                vectorCase.caseName === 'noncanonical-coefficient-encoding',
        );

        expect(noncanonicalCase).toBeDefined();
        expect(noncanonicalCase?.trace).toMatchObject({
            expectedLogicalRejectionLayer: 'canonical-statement-decoder',
        });
        expect(
            noncanonicalCase?.statementMatrixCoefficients?.[0]?.[0]?.[0],
        ).toBe(linearProofBackendVectors.parameterSet.coefficientModulus);
    });

    it('records structured decoder spans for canonical proof bytes', () => {
        const validCase = linearProofBackendVectors.cases.find(
            (vectorCase) => vectorCase.caseName === 'valid-small-linear-proof',
        );

        expect(validCase).toBeDefined();
        expect(validCase?.trace?.decodedProofFieldLengths).toMatchObject({
            fullProofBytes: 22923,
            terminalPadding: {
                name: 'terminalPadding',
            },
        });
        expect(
            validCase?.trace?.decodedProofFieldLengths?.fields?.map(
                (field) => field.name,
            ),
        ).toEqual([
            'commitmentTargetVector',
            'hashMaskVector',
            'compressedCommitmentVector',
            'challengePolynomial',
            'hintVector',
            'shortResponseVector',
            'randomnessResponseVector',
            'euclideanResponseVector',
            'infinityResponseVector',
        ]);
        const fields = validCase?.trace?.decodedProofFieldLengths?.fields ?? [];
        for (const [fieldIndex, field] of fields.entries()) {
            expect(field.bitLength).toBeGreaterThan(0);
            if (fieldIndex > 0) {
                expect(field.bitOffset).toBe(
                    fields[fieldIndex - 1]?.bitOffset +
                        (fields[fieldIndex - 1]?.bitLength ?? 0),
                );
            }
        }
    });

    it('records receiver-key upstream oracle provenance without treating it as production closure', () => {
        const caseNames = new Set(
            receiverKeyLinearProofBackendVectors.cases.map(
                (vectorCase) => vectorCase.caseName,
            ),
        );

        expect(
            receiverKeyLinearProofBackendVectors.generatedFromUpstreamLaZer,
        ).toBe(true);
        expect(receiverKeyLinearProofBackendVectors.generationStatus).toBe(
            'generated-with-profile-warning',
        );
        expect(
            receiverKeyLinearProofBackendVectors.targetCoefficientRepresentation,
        ).toBe('centeredSignedSourceModulus');
        expect(
            receiverKeyLinearProofBackendVectors.provenance
                .upstreamRepositoryUrl,
        ).toBe('https://github.com/lazer-crypto/lazer');
        expect(
            receiverKeyLinearProofBackendVectors.provenance.upstreamCommitHash,
        ).toMatch(/^[a-f0-9]{40}$/u);
        expect(
            receiverKeyLinearProofBackendVectors.provenance.dockerfileSha256,
        ).toMatch(/^[a-f0-9]{64}$/u);
        expect(
            receiverKeyLinearProofBackendVectors.provenance
                .receiverKeyParameterSourceSha256,
        ).toMatch(/^[a-f0-9]{64}$/u);
        expect(
            receiverKeyLinearProofBackendVectors.provenance.vectorEmitterSha256,
        ).toMatch(/^[a-f0-9]{64}$/u);
        expect(
            receiverKeyLinearProofBackendVectors.provenance.profileWarning,
        ).toContain('not production closure');
        expect(
            receiverKeyLinearProofBackendVectors.provenance.licenseNote,
        ).toContain('offline vector oracle');
        for (const requiredCaseName of receiverKeyLinearProofBackendVectors.requiredCaseNames) {
            expect(caseNames.has(requiredCaseName)).toBe(true);
        }
    });

    it('keeps receiver-key vectors public-only and bound to the receiver-key proof encoding', () => {
        const discoveredKeys = new Set<string>();
        collectObjectKeys(receiverKeyLinearProofBackendVectors, discoveredKeys);
        for (const forbiddenKey of forbiddenPublicVectorKeys) {
            expect(discoveredKeys.has(forbiddenKey)).toBe(false);
        }

        expect(
            receiverKeyLinearProofBackendVectors.parameterSet
                .coefficientModulus,
        ).toBe(12_289);
        expect(
            receiverKeyLinearProofBackendVectors.proofEncoding
                .coefficientModulus,
        ).toBe('274877908477');
        for (const vectorCase of receiverKeyLinearProofBackendVectors.cases) {
            expect(vectorCase.upstreamVectorAvailable).toBe(true);
            expect(vectorCase.expectedOutcome).toMatch(/^(accept|reject)$/u);
            expect(vectorCase.proofEncoding?.profileId).toBe(
                receiverKeyLinearProofBackendVectors.proofEncoding.profileId,
            );
            expect(vectorCase.proofHex).toMatch(/^[a-f0-9]+$/u);
            expect(vectorCase.publicRandomnessHex).toMatch(/^[a-f0-9]{64}$/u);
            expect(vectorCase.statementMatrixCoefficients).toHaveLength(4);
            expect(vectorCase.targetVectorCoefficients).toHaveLength(4);
            expect(vectorCase.targetCoefficientRepresentation).toBe(
                'centeredSignedSourceModulus',
            );
        }
    });

    it('records receiver-key decoder and canonical-statement rejection layers', () => {
        const truncatedProofCase =
            receiverKeyLinearProofBackendVectors.cases.find(
                (vectorCase) =>
                    vectorCase.caseName === 'truncated-receiver-key-proof',
            );
        const extendedProofCase =
            receiverKeyLinearProofBackendVectors.cases.find(
                (vectorCase) =>
                    vectorCase.caseName === 'extended-receiver-key-proof',
            );
        const noncanonicalCase =
            receiverKeyLinearProofBackendVectors.cases.find(
                (vectorCase) =>
                    vectorCase.caseName ===
                    'noncanonical-receiver-key-coefficient-encoding',
            );

        expect(truncatedProofCase?.trace).toMatchObject({
            expectedLogicalRejectionLayer: 'proof-decoder',
            upstreamVerifierAccepted: false,
        });
        expect(
            truncatedProofCase?.trace?.decodedProofFieldLengths?.decoderError,
        ).toBe('proof encoding has no terminal padding bit');
        expect(extendedProofCase?.trace).toMatchObject({
            expectedLogicalRejectionLayer: 'proof-decoder',
            upstreamVerifierAccepted: true,
        });
        expect(
            extendedProofCase?.trace?.decodedProofFieldLengths?.decoderError,
        ).toBe('proof encoding contains trailing data');
        expect(noncanonicalCase?.trace).toMatchObject({
            expectedLogicalRejectionLayer: 'canonical-statement-decoder',
        });
        expect(
            noncanonicalCase?.statementMatrixCoefficients?.[0]?.[0]?.[0],
        ).toBe(
            receiverKeyLinearProofBackendVectors.parameterSet
                .coefficientModulus,
        );
    });

    it('records receiver-key preflight transcript mutations for public binding', () => {
        const validCase = receiverKeyLinearProofBackendVectors.cases.find(
            (vectorCase) =>
                vectorCase.caseName === 'valid-receiver-key-linear-proof',
        );
        const casesWithChangedPreflightHash = [
            'mutated-receiver-key-statement-matrix',
            'mutated-receiver-key-target-vector',
            'mutated-receiver-key-proof-byte',
            'wrong-receiver-key-public-randomness',
            'truncated-receiver-key-proof',
            'extended-receiver-key-proof',
        ];

        expect(
            validCase?.trace?.sealedLatticePreflightTranscript,
        ).toMatchObject({
            domain: 'sealed.vote/internal/linear-proof-preflight-v1',
            hash: 'SHAKE128-256',
        });
        const validPreflightHash =
            validCase?.trace?.sealedLatticePreflightTranscript
                ?.preflightTranscriptHash;
        expect(validPreflightHash).toMatch(lowercaseShake128HashPattern);
        for (const caseName of casesWithChangedPreflightHash) {
            const mutatedCase = receiverKeyLinearProofBackendVectors.cases.find(
                (vectorCase) => vectorCase.caseName === caseName,
            );

            expect(
                mutatedCase?.trace?.sealedLatticePreflightTranscript
                    ?.preflightTranscriptHash,
            ).toMatch(lowercaseShake128HashPattern);
            expect(
                mutatedCase?.trace?.sealedLatticePreflightTranscript
                    ?.preflightTranscriptHash,
            ).not.toBe(validPreflightHash);
        }
    });

    it('records compiler-derived encoded-score field-row oracle provenance', () => {
        const caseNames = new Set(
            ballotFieldLinearProofBackendVectors.cases.map(
                (vectorCase) => vectorCase.caseName,
            ),
        );

        expect(
            ballotFieldLinearProofBackendVectors.generatedFromUpstreamLaZer,
        ).toBe(true);
        expect(ballotFieldLinearProofBackendVectors.generationStatus).toBe(
            'generated-with-profile-warning',
        );
        expect(ballotFieldLinearProofBackendVectors.projectionCoverage).toBe(
            'encoded-score-field-rows-only',
        );
        expect(
            ballotFieldLinearProofBackendVectors.provenance
                .upstreamRepositoryUrl,
        ).toBe('https://github.com/lazer-crypto/lazer');
        expect(
            ballotFieldLinearProofBackendVectors.provenance.upstreamCommitHash,
        ).toMatch(/^[a-f0-9]{40}$/u);
        expect(
            ballotFieldLinearProofBackendVectors.provenance
                .ballotFieldParameterSourceSha256,
        ).toMatch(/^[a-f0-9]{64}$/u);
        expect(
            ballotFieldLinearProofBackendVectors.provenance
                .oracleInputGeneratorSha256,
        ).toMatch(/^[a-f0-9]{64}$/u);
        expect(
            ballotFieldLinearProofBackendVectors.provenance
                .generatedHeaderSha256,
        ).toMatch(/^[a-f0-9]{64}$/u);
        expect(
            ballotFieldLinearProofBackendVectors.provenance.profileWarning,
        ).toContain('encoded-score field-row projection');
        expect(
            ballotFieldLinearProofBackendVectors.matrixCoefficientRepresentation,
        ).toBe('canonicalUnsignedSourceModulus');
        expect(
            ballotFieldLinearProofBackendVectors.targetCoefficientRepresentation,
        ).toBe('canonicalUnsignedSourceModulus');
        for (const requiredCaseName of ballotFieldLinearProofBackendVectors.requiredCaseNames) {
            expect(caseNames.has(requiredCaseName)).toBe(true);
        }
    });

    it('keeps encoded-score field vectors public-only and profile-shaped', () => {
        const discoveredKeys = new Set<string>();
        collectObjectKeys(ballotFieldLinearProofBackendVectors, discoveredKeys);
        for (const forbiddenKey of forbiddenPublicVectorKeys) {
            expect(discoveredKeys.has(forbiddenKey)).toBe(false);
        }

        expect(ballotFieldLinearProofBackendVectors.parameterSet).toMatchObject(
            {
                coefficientModulus: 65_537,
                expectedProofSizeBytes: 46_417,
                profileId: 'encoded-score-field-linear-proof-parameter-v1',
                ringDegree: 64,
                statementColumns: 176,
                statementRows: 70,
                witnessL2BoundSquared: 65_536,
            },
        );
        expect(
            ballotFieldLinearProofBackendVectors.proofEncoding,
        ).toMatchObject({
            coefficientModulus: '70368744177829',
            compressedCoefficientBitLength: 35,
            fullSizeCoefficientBitLength: 47,
            profileId: 'encoded-score-field-linear-proof-encoding-v1',
            randomnessResponseVectorLength: 41,
            shortResponseVectorLength: 177,
        });
        expect(
            ballotFieldLinearProofBackendVectors.linearStatement
                .statementMatrixCoefficients,
        ).toHaveLength(70);
        expect(
            ballotFieldLinearProofBackendVectors.linearStatement
                .projectionCoverage,
        ).toBe('encoded-score-field-rows-only');
        expect(
            ballotFieldLinearProofBackendVectors.linearStatement
                .statementMatrixCoefficients[0],
        ).toHaveLength(176);
        expect(
            ballotFieldLinearProofBackendVectors.linearStatement
                .statementMatrixCoefficients[0]?.[0],
        ).toHaveLength(64);
        expect(
            ballotFieldLinearProofBackendVectors.linearStatement
                .targetVectorCoefficients,
        ).toHaveLength(70);
        expect(ballotFieldLinearProofBackendVectors.proofHex).toHaveLength(
            ballotFieldLinearProofBackendVectors.expectedProofSizeBytes * 2,
        );
        expect(
            ballotFieldLinearProofBackendVectors.publicRandomnessHex,
        ).toMatch(/^[a-f0-9]{64}$/u);
    });

    it('records compact encoded-score field mutations without duplicating the public matrix', () => {
        const validCase = ballotFieldLinearProofBackendVectors.cases.find(
            (vectorCase) =>
                vectorCase.caseName ===
                'valid-encoded-score-field-linear-proof',
        );
        const matrixMutationCase =
            ballotFieldLinearProofBackendVectors.cases.find(
                (vectorCase) =>
                    vectorCase.caseName ===
                    'mutated-encoded-score-field-statement-matrix',
            );
        const targetMutationCase =
            ballotFieldLinearProofBackendVectors.cases.find(
                (vectorCase) =>
                    vectorCase.caseName ===
                    'mutated-encoded-score-field-target-vector',
            );
        const noncanonicalCase =
            ballotFieldLinearProofBackendVectors.cases.find(
                (vectorCase) =>
                    vectorCase.caseName ===
                    'noncanonical-encoded-score-field-coefficient-encoding',
            );

        expect(validCase).toBeDefined();
        expect(validCase).not.toHaveProperty('proofHex');
        expect(validCase).not.toHaveProperty('publicRandomnessHex');
        expect(validCase).not.toHaveProperty('statementMatrixPatch');
        expect(matrixMutationCase?.statementMatrixPatch).toEqual({
            coefficient: 2,
            coefficientIndex: 0,
            columnIndex: 0,
            rowIndex: 0,
        });
        expect(targetMutationCase?.targetVectorPatch).toEqual({
            coefficient: 0,
            coefficientIndex: 0,
            rowIndex: 0,
        });
        expect(noncanonicalCase?.statementMatrixPatch).toEqual({
            coefficient: 65_537,
            coefficientIndex: 0,
            columnIndex: 0,
            rowIndex: 0,
        });
    });

    it('records encoded-score field rejection layers and decoder spans', () => {
        const validCase = ballotFieldLinearProofBackendVectors.cases.find(
            (vectorCase) =>
                vectorCase.caseName ===
                'valid-encoded-score-field-linear-proof',
        );
        const rejectedByUpstream = new Set([
            'mutated-encoded-score-field-statement-matrix',
            'mutated-encoded-score-field-target-vector',
            'mutated-encoded-score-field-proof-byte',
            'wrong-encoded-score-field-public-randomness',
            'truncated-encoded-score-field-proof',
        ]);
        const extendedProofCase =
            ballotFieldLinearProofBackendVectors.cases.find(
                (vectorCase) =>
                    vectorCase.caseName ===
                    'extended-encoded-score-field-proof',
            );

        expect(validCase?.trace.decodedProofFieldLengths).toMatchObject({
            fullProofBytes: 46_417,
            terminalPadding: {
                name: 'terminalPadding',
            },
        });
        expect(
            validCase?.trace.decodedProofFieldLengths?.fields?.map(
                (field) => field.name,
            ),
        ).toEqual([
            'commitmentTargetVector',
            'hashMaskVector',
            'compressedCommitmentVector',
            'challengePolynomial',
            'hintVector',
            'shortResponseVector',
            'randomnessResponseVector',
            'euclideanResponseVector',
            'infinityResponseVector',
        ]);
        for (const vectorCase of ballotFieldLinearProofBackendVectors.cases) {
            if (rejectedByUpstream.has(vectorCase.caseName)) {
                expect(vectorCase.trace).toMatchObject({
                    upstreamVerifierAccepted: false,
                });
            }
        }
        expect(extendedProofCase?.trace).toMatchObject({
            expectedLogicalRejectionLayer: 'proof-decoder',
            upstreamVerifierAccepted: true,
        });
        expect(
            extendedProofCase?.trace.decodedProofFieldLengths?.decoderError,
        ).toBe('proof encoding contains trailing data');
    });
});

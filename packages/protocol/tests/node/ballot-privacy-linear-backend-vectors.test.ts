import { describe, expect, it } from 'vitest';

import linearProofBackendVectorsJson from '../../../../test-vectors/ballot-privacy/proof-backend-linear-vectors.json';

type LinearProofBackendVectorCase = {
    readonly caseName: string;
    readonly expectedOutcome: string;
    readonly upstreamVectorAvailable: boolean;
    readonly proofHex: string | null;
    readonly publicRandomnessHex: string | null;
    readonly statementMatrixCoefficients?: readonly (readonly (readonly number[])[])[];
    readonly targetVectorCoefficients?: readonly (readonly number[])[];
    readonly trace?: {
        readonly expectedLogicalRejectionLayer?: string;
        readonly upstreamVerifierAccepted?: boolean;
    };
};

type LinearProofBackendVectorFile = {
    readonly generatedFromUpstreamLaZer: boolean;
    readonly generationStatus: string;
    readonly parameterSet: {
        readonly coefficientModulus: number;
    };
    readonly provenance: {
        readonly upstreamRepositoryUrl: string;
        readonly upstreamCommitHash: string;
        readonly dockerfileSha256: string;
        readonly vectorEmitterSha256: string;
        readonly licenseNote: string;
    };
    readonly requiredCaseNames: readonly string[];
    readonly cases: readonly LinearProofBackendVectorCase[];
};

const linearProofBackendVectors =
    linearProofBackendVectorsJson as LinearProofBackendVectorFile;
const forbiddenPublicVectorKeys = new Set([
    'privateWitness',
    'proofRandomness',
    'proverCoins',
    'receiverSecret',
    'secret',
    'witness',
]);

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
        expect(linearProofBackendVectors.provenance.upstreamRepositoryUrl).toBe(
            'https://github.com/lazer-crypto/lazer',
        );
        expect(linearProofBackendVectors.provenance.upstreamCommitHash).toMatch(
            /^[a-f0-9]{40}$/u,
        );
        expect(linearProofBackendVectors.provenance.dockerfileSha256).toMatch(
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
            expect(vectorCase.proofHex).toMatch(/^[a-f0-9]+$/u);
            expect(vectorCase.publicRandomnessHex).toMatch(/^[a-f0-9]{64}$/u);
            expect(vectorCase.statementMatrixCoefficients).toHaveLength(4);
            expect(vectorCase.targetVectorCoefficients).toHaveLength(4);
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
});

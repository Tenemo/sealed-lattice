import { describe, expect, it } from 'vitest';

import receiverKeyVectorsJson from '#test-vectors/ballot-privacy/receiver-key-proof-vectors.json';

type ReceiverKeyVectorCase = {
    readonly caseName: string;
    readonly expectedOutcome: 'accept' | 'reject';
    readonly proofConstructionAccepted: boolean;
    readonly receiverPublicKey?: {
        readonly receiverPublicKeyDigest: string;
    };
    readonly receiverKeyProof?: {
        readonly proofRoot: string;
        readonly receiverKeyProofRoot: string;
    };
    readonly backendStatement?: {
        readonly backendStatementDigest: string;
        readonly backendStatementFormat: string;
        readonly bounds: readonly unknown[];
        readonly columnCount: number;
        readonly digestExpandedRowCount: number;
        readonly explicitRowCount: number;
        readonly keyMaterialDigest: string;
        readonly matrixDigest: string;
        readonly objectType: string;
        readonly receiverPublicKeyDigest: string;
        readonly relationLabel: string;
        readonly rowBatches: readonly {
            readonly batchKind: string;
            readonly modulus: string;
            readonly rowCount: number;
            readonly rowKind: string;
            readonly rowOffset: number;
        }[];
        readonly rowCount: number;
        readonly targetVectorDigest: string;
        readonly variableColumns: readonly unknown[];
    };
    readonly linearStatement?: {
        readonly coefficientModulus: '12289';
        readonly objectType: 'ReceiverKeyLinearProofStatement';
        readonly relation: 'A*w + t = 0';
        readonly ringDegree: 256;
        readonly sourceRing: 'Z_q[X]/(X^256 + 1)';
        readonly statementColumns: 8;
        readonly statementDigest: string;
        readonly statementMatrixCoefficients: readonly (readonly (readonly number[])[])[];
        readonly statementMatrixDigest: string;
        readonly statementProfileId: 'receiver-key-linear-module-lwe-statement-v1';
        readonly statementRows: 4;
        readonly targetVectorCoefficients: readonly (readonly number[])[];
        readonly targetVectorDigest: string;
        readonly witnessInfinityNormBound: 2;
        readonly witnessL2BoundSquared: '8192';
    };
    readonly refusalMessages?: readonly string[];
    readonly trace: {
        readonly backendStatementDigest?: string;
        readonly baselineBackendStatementDigest?: string;
        readonly baselineLinearStatementDigest?: string;
        readonly expectedDigestChanged?: true;
        readonly expectedLogicalRejectionLayer?:
            | 'receiver-key-proof-construction'
            | 'backend-statement-preflight'
            | 'linear-statement-preflight'
            | 'receiver-key-proof-shell';
        readonly linearStatementDigest?: string;
    };
};

type ReceiverKeyVectorFile = {
    readonly objectType: 'ReceiverKeyProofBackendStatementVectors';
    readonly objectVersion: 1;
    readonly generationStatus: 'generated';
    readonly profileId: 'receiver-key-proof-backend-statement-v1';
    readonly requiredCaseNames: readonly string[];
    readonly statementFormat: 'SparseSignedIntegerBackendStatement-v1 + receiver-key-linear-module-lwe-statement-v1';
    readonly cases: readonly ReceiverKeyVectorCase[];
};

const receiverKeyVectors = receiverKeyVectorsJson as ReceiverKeyVectorFile;

const forbiddenPublicVectorKeys = new Set([
    'ciphertextChunks',
    'errorVector',
    'openingRandomness',
    'privateWitness',
    'proofRandomness',
    'publicKeyVector',
    'receiverShareVector',
    'secretState',
    'secretVector',
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

const caseByName = (caseName: string): ReceiverKeyVectorCase => {
    const vectorCase = receiverKeyVectors.cases.find(
        (candidate) => candidate.caseName === caseName,
    );
    if (vectorCase === undefined) {
        throw new Error(`Missing receiver-key vector case ${caseName}.`);
    }

    return vectorCase;
};

describe('ballot privacy receiver-key proof vectors', () => {
    it('records all required receiver-key vectors without witness material', () => {
        const discoveredKeys = new Set<string>();
        const caseNames = new Set(
            receiverKeyVectors.cases.map((vectorCase) => vectorCase.caseName),
        );
        collectObjectKeys(receiverKeyVectors, discoveredKeys);

        expect(receiverKeyVectors).toMatchObject({
            generationStatus: 'generated',
            objectType: 'ReceiverKeyProofBackendStatementVectors',
            objectVersion: 1,
            profileId: 'receiver-key-proof-backend-statement-v1',
            statementFormat:
                'SparseSignedIntegerBackendStatement-v1 + receiver-key-linear-module-lwe-statement-v1',
        });
        for (const requiredCaseName of receiverKeyVectors.requiredCaseNames) {
            expect(caseNames.has(requiredCaseName)).toBe(true);
        }
        for (const forbiddenKey of forbiddenPublicVectorKeys) {
            expect(discoveredKeys.has(forbiddenKey)).toBe(false);
        }
    });

    it('binds the valid receiver-key proof shell to a concrete backend statement', () => {
        const vectorCase = caseByName(
            'valid-receiver-key-proof-backend-statement',
        );

        expect(vectorCase).toMatchObject({
            expectedOutcome: 'accept',
            proofConstructionAccepted: true,
        });
        expect(vectorCase.receiverPublicKey?.receiverPublicKeyDigest).toBe(
            vectorCase.backendStatement?.receiverPublicKeyDigest,
        );
        expect(vectorCase.receiverKeyProof?.proofRoot).toMatch(
            /^[a-f0-9]{128}$/u,
        );
        expect(vectorCase.receiverKeyProof?.receiverKeyProofRoot).toMatch(
            /^[a-f0-9]{128}$/u,
        );
        expect(vectorCase.backendStatement).toMatchObject({
            backendStatementFormat: 'SparseSignedIntegerBackendStatement-v1',
            columnCount: 2_048,
            digestExpandedRowCount: 1_024,
            explicitRowCount: 0,
            objectType: 'ReceiverKeyProofBackendStatement',
            relationLabel: 'ReceiverKeyWellFormednessRelation',
            rowCount: 1_024,
        });
        expect(vectorCase.backendStatement?.backendStatementDigest).toBe(
            vectorCase.trace.backendStatementDigest,
        );
        expect(vectorCase.linearStatement).toMatchObject({
            coefficientModulus: '12289',
            objectType: 'ReceiverKeyLinearProofStatement',
            relation: 'A*w + t = 0',
            ringDegree: 256,
            sourceRing: 'Z_q[X]/(X^256 + 1)',
            statementColumns: 8,
            statementProfileId: 'receiver-key-linear-module-lwe-statement-v1',
            statementRows: 4,
            witnessInfinityNormBound: 2,
            witnessL2BoundSquared: '8192',
        });
        expect(vectorCase.linearStatement?.statementDigest).toBe(
            vectorCase.trace.linearStatementDigest,
        );
        expect(
            vectorCase.linearStatement?.statementMatrixCoefficients,
        ).toHaveLength(4);
        expect(
            vectorCase.linearStatement?.statementMatrixCoefficients[0],
        ).toHaveLength(8);
        expect(
            vectorCase.linearStatement?.targetVectorCoefficients,
        ).toHaveLength(4);
        expect(vectorCase.backendStatement?.variableColumns).toHaveLength(
            2_048,
        );
        expect(vectorCase.backendStatement?.bounds).toHaveLength(2);
        expect(vectorCase.backendStatement?.rowBatches).toEqual([
            expect.objectContaining({
                batchKind: 'DigestExpandedRows',
                modulus: '12289',
                rowCount: 1_024,
                rowKind: 'ReceiverKeyEquation',
                rowOffset: 0,
            }),
        ]);
    });

    it('records context changes, construction refusals, and backend preflight refusals distinctly', () => {
        const changedManifestCase = caseByName(
            'changed-manifest-changes-backend-statement-digest',
        );
        const wrongSeedCase = caseByName('wrong-public-matrix-seed-rejects');
        const oversizeSecretCase = caseByName(
            'oversize-secret-witness-rejects',
        );
        const backendPreflightCase = caseByName(
            'noncanonical-backend-modulus-rejects',
        );
        const proofShellCase = caseByName('mutated-proof-root-rejects');
        const linearPreflightCase = caseByName(
            'mutated-linear-statement-target-rejects',
        );

        expect(changedManifestCase.trace.expectedDigestChanged).toBe(true);
        expect(
            changedManifestCase.trace.baselineBackendStatementDigest,
        ).not.toBe(changedManifestCase.trace.backendStatementDigest);
        expect(
            changedManifestCase.trace.baselineLinearStatementDigest,
        ).not.toBe(changedManifestCase.trace.linearStatementDigest);
        expect(wrongSeedCase).toMatchObject({
            expectedOutcome: 'reject',
            proofConstructionAccepted: false,
            trace: {
                expectedLogicalRejectionLayer:
                    'receiver-key-proof-construction',
            },
        });
        expect(wrongSeedCase.refusalMessages?.join(' ')).toContain(
            'public matrix seed is not roster-bound',
        );
        expect(oversizeSecretCase.refusalMessages?.join(' ')).toContain(
            'centered-binomial norm bound',
        );
        expect(backendPreflightCase).toMatchObject({
            expectedOutcome: 'reject',
            proofConstructionAccepted: true,
            trace: {
                expectedLogicalRejectionLayer: 'backend-statement-preflight',
            },
        });
        expect(
            backendPreflightCase.backendStatement?.rowBatches[0]?.modulus,
        ).toBe('012289');
        expect(proofShellCase).toMatchObject({
            expectedOutcome: 'reject',
            proofConstructionAccepted: true,
            trace: {
                expectedLogicalRejectionLayer: 'receiver-key-proof-shell',
            },
        });
        expect(linearPreflightCase).toMatchObject({
            expectedOutcome: 'reject',
            proofConstructionAccepted: true,
            trace: {
                expectedLogicalRejectionLayer: 'linear-statement-preflight',
            },
        });
    });
});

import { beforeEach, describe, expect, it, vi } from 'vitest';

type JsonRecord = Record<string, unknown>;

let mockKernel: {
    readonly aggregateDirectEncryptedBallotPackages: ReturnType<typeof vi.fn>;
    readonly createDirectEncryptedBallotPackages: ReturnType<typeof vi.fn>;
    readonly verifyCollectiveBgvSetup: ReturnType<typeof vi.fn>;
    readonly verifyDirectEncryptedBallotPackage: ReturnType<typeof vi.fn>;
};

vi.mock('../../dist/kernel.js', () => ({
    loadTranscriptCoreKernel: () => Promise.resolve(mockKernel),
}));

const publicPackage = await import('../../dist/index.js');

const protocolHash =
    '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

const acceptedSetupHandoff = {
    objectType: 'CollectiveBgvAcceptedSetupHandoff',
    objectVersion: 1,
    acceptedSetupHandoffRoot: protocolHash,
    directBallotEncryptionHandoff: {
        objectType: 'DirectBallotEncryptionHandoff',
        soundnessCertificateHash: protocolHash,
    },
} as unknown as Parameters<
    typeof publicPackage.createDirectEncryptedBallotPackages
>[0]['acceptedSetupHandoff'];

const acceptedPublicKeyMaterial = {
    objectType: 'DirectBallotAcceptedPublicKeyMaterial',
    objectVersion: 1,
    acceptedSetupHandoffRoot: protocolHash,
    bgvPublicKeyRoot: protocolHash,
} as unknown as Parameters<
    typeof publicPackage.createDirectEncryptedBallotPackages
>[0]['acceptedPublicKeyMaterial'];

const encryptedBallotPackage = {
    objectType: 'EncryptedBallotPackage',
    objectVersion: 1,
    packageRoot: protocolHash,
} as unknown;

const proofChunks = [
    {
        objectType: 'BallotProofChunk',
        objectVersion: 1,
        chunkIndex: 0,
        bytesHex: 'abcd',
    },
] as unknown as Parameters<
    typeof publicPackage.verifyDirectEncryptedBallotPackage
>[0]['proofChunks'];

const ballot = {
    voterIdentity: 'voter-setup-output-public-package',
    voterRosterPosition: 0,
    actionContextHash: protocolHash,
    recoveryEpoch: 0,
    deviceEpoch: 0,
    scores: [10, 9, 8, 7, 6, 5, 4, 3, 2, 1],
} as unknown as Parameters<
    typeof publicPackage.createDirectEncryptedBallotPackages
>[0]['ballots'][number];

describe('direct encrypted ballot public package API', () => {
    beforeEach(() => {
        mockKernel = {
            aggregateDirectEncryptedBallotPackages: vi.fn(() => ({
                operation: 'aggregateDirectEncryptedBallotPackages',
            })),
            createDirectEncryptedBallotPackages: vi.fn(() => ({
                operation: 'createDirectEncryptedBallotPackages',
            })),
            verifyCollectiveBgvSetup: vi.fn(() => ({
                ok: true,
                operation: 'verifyCollectiveBgvSetupPackage',
                verifierStatus: 'accepted',
                acceptedSetupHandoff,
                acceptedPublicKeyMaterial,
            })),
            verifyDirectEncryptedBallotPackage: vi.fn(() => ({
                operation: 'verifyDirectEncryptedBallotPackage',
            })),
        };
    });

    it('forwards accepted setup verifier outputs through package creation, verification, and aggregation', async () => {
        const setupVerification = await publicPackage.verifySetupPackage({
            setupPackage: {
                objectType: 'CollectiveBgvSetupPackage',
                objectVersion: 1,
            },
        });

        expect(setupVerification.acceptedSetupHandoff).toBe(
            acceptedSetupHandoff,
        );
        expect(setupVerification.acceptedPublicKeyMaterial).toBe(
            acceptedPublicKeyMaterial,
        );
        const setupAcceptedPublicKeyMaterial =
            setupVerification.acceptedPublicKeyMaterial;
        const setupAcceptedHandoff = setupVerification.acceptedSetupHandoff;
        if (
            setupAcceptedPublicKeyMaterial === undefined ||
            setupAcceptedHandoff === undefined
        ) {
            throw new Error(
                'accepted setup verification did not return direct ballot handoff material.',
            );
        }

        await publicPackage.createDirectEncryptedBallotPackages({
            acceptedPublicKeyMaterial: setupAcceptedPublicKeyMaterial,
            acceptedSetupHandoff: setupAcceptedHandoff,
            ballots: [ballot],
        });

        const creationInput = mockKernel.createDirectEncryptedBallotPackages
            .mock.calls[0]?.[0] as JsonRecord | undefined;
        expect(creationInput?.acceptedSetupHandoff).toBe(acceptedSetupHandoff);
        expect(creationInput?.acceptedPublicKeyMaterial).toBe(
            acceptedPublicKeyMaterial,
        );
        expect(creationInput).not.toHaveProperty('setupPackage');
        expect(creationInput).not.toHaveProperty('setupPublicMaterial');
        const ballotEncryptionRandomness =
            creationInput?.ballotEncryptionRandomness as JsonRecord | undefined;
        const proofMaskRandomness = creationInput?.proofMaskRandomness as
            | JsonRecord
            | undefined;
        expect(ballotEncryptionRandomness?.source).toBe('fresh-csprng');
        expect(proofMaskRandomness?.source).toBe('fresh-csprng');
        expect(ballotEncryptionRandomness?.encryptionSeedHexes).toStrictEqual([
            expect.stringMatching(/^[0-9a-f]{64}$/u),
        ]);
        expect(proofMaskRandomness?.ballotProofRandomnessHexes).toStrictEqual([
            expect.stringMatching(/^[0-9a-f]{64}$/u),
        ]);

        await publicPackage.verifyDirectEncryptedBallotPackage({
            acceptedPublicKeyMaterial: setupAcceptedPublicKeyMaterial,
            acceptedSetupHandoff: setupAcceptedHandoff,
            voterSigningPublicKeyHash: protocolHash,
            encryptedBallotPackage,
            proofChunks,
        });

        const verificationInput = mockKernel.verifyDirectEncryptedBallotPackage
            .mock.calls[0]?.[0] as JsonRecord | undefined;
        expect(verificationInput?.acceptedSetupHandoff).toBe(
            acceptedSetupHandoff,
        );
        expect(verificationInput?.acceptedPublicKeyMaterial).toBe(
            acceptedPublicKeyMaterial,
        );
        expect(verificationInput).not.toHaveProperty('setupPackage');
        expect(verificationInput).not.toHaveProperty('setupPublicMaterial');

        const encryptedBallotPackages = [
            {
                voterSigningPublicKeyHash: protocolHash,
                encryptedBallotPackage,
                proofChunks,
            },
        ] as const;
        await publicPackage.aggregateDirectEncryptedBallotPackages({
            acceptedPublicKeyMaterial: setupAcceptedPublicKeyMaterial,
            acceptedSetupHandoff: setupAcceptedHandoff,
            encryptedBallotPackages,
        });

        const aggregationInput = mockKernel
            .aggregateDirectEncryptedBallotPackages.mock.calls[0]?.[0] as
            | JsonRecord
            | undefined;
        expect(aggregationInput?.acceptedSetupHandoff).toBe(
            acceptedSetupHandoff,
        );
        expect(aggregationInput?.acceptedPublicKeyMaterial).toBe(
            acceptedPublicKeyMaterial,
        );
        expect(aggregationInput?.encryptedBallotPackages).toBe(
            encryptedBallotPackages,
        );
        expect(aggregationInput).not.toHaveProperty('setupPackage');
        expect(aggregationInput).not.toHaveProperty('setupPublicMaterial');
    });
});

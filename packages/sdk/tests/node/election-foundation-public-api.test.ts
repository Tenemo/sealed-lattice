import type { VerificationResult } from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import * as publicApiRuntime from '../../dist/index.js';

import { deriveCanonicalObjectHash } from '#packages/crypto/src/index';
import type {
    FoundationBoardCandidate,
    FoundationBoardSessionInput,
} from '#packages/sdk/src/index';
import { createAuthenticatedComplaintTestVector } from '#packages/wasm/tests/foundation-board-test-vectors';

type DeriveCollectiveBgvSetupRosterHash = (
    entries: readonly Readonly<{
        readonly rosterPosition: number;
        readonly trusteeIdentity: string;
        readonly signingPublicKeyHash: string;
    }>[],
) => string;
type TestedFoundationBoardSession = Readonly<{
    cancel(): void;
    ingest(
        canonicalCarrierBytes: Uint8Array,
    ): VerificationResult<FoundationBoardCandidate>;
    requireCompleteCarrierGraph(): VerificationResult<undefined>;
}>;
type CreateFoundationBoardSession = (
    configuration: FoundationBoardSessionInput,
) => Promise<VerificationResult<TestedFoundationBoardSession>>;
type FoundationBoardCandidateObjectHash = (
    candidate: FoundationBoardCandidate,
) => Uint8Array;

const publicApiRuntimeRecord = publicApiRuntime as Record<string, unknown>;
const deriveCollectiveBgvSetupRosterHash =
    publicApiRuntimeRecord.deriveCollectiveBgvSetupRosterHash as DeriveCollectiveBgvSetupRosterHash;
const createFoundationBoardSession =
    publicApiRuntimeRecord.createFoundationBoardSession as CreateFoundationBoardSession;
const foundationBoardCandidateObjectHash =
    publicApiRuntimeRecord.foundationBoardCandidateObjectHash as FoundationBoardCandidateObjectHash;

const expectedPublicRuntimeExportNames = [
    'ThresholdParameterDerivationError',
    'createFoundationBoardSession',
    'deriveCollectiveBgvSetupRosterHash',
    'deriveFrozenRosterParameters',
    'derivePollSpecHash',
    'deriveThresholdParameters',
    'deriveThresholdParametersHash',
    'deriveValidatedFirstValidOrder',
    'foundationBoardCandidateObjectHash',
    'generateTargetDecryptionShareProofMaterial',
    'isActionCurrentForRecoveryEpoch',
    'validatePollSpec',
    'verifyBoardConsistency',
    'verifyCastReceiptShell',
    'verifyCloseRecordShell',
    'verifyPrivateVssShare',
    'verifyRecoveryEpochUpdate',
    'verifyRosterExternalAcceptance',
    'verifyRosterManifestTranscript',
    'verifySetupPackage',
    'verifyTargetDecryptionResult',
] as const;

describe('election foundation public package API in Node', () => {
    it('exposes safe runtime functions and keeps runtime exports callable', () => {
        const runtimeExportNames = Object.keys(publicApiRuntimeRecord).sort();

        expect(runtimeExportNames).toEqual(expectedPublicRuntimeExportNames);
        for (const publicFunctionName of runtimeExportNames) {
            expect(
                typeof publicApiRuntimeRecord[publicFunctionName],
                publicFunctionName,
            ).toBe('function');
        }
    });

    it('opens the packaged canonical board boundary with an authenticated complaint carrier', async () => {
        const authenticatedComplaint = createAuthenticatedComplaintTestVector();
        const opened = await createFoundationBoardSession({
            actionContextHash: new Uint8Array(64).fill(0x33),
            canonicalRosterBytes: authenticatedComplaint.canonicalRosterBytes,
            ceremonyContextHash: new Uint8Array(64).fill(0x22),
            suiteIdentifier: new Uint8Array(64).fill(0x11),
        });
        expect(opened.isValid).toBe(true);
        if (!opened.isValid) {
            throw new Error(opened.refusalReason);
        }
        try {
            expect(opened.value.ingest(Uint8Array.from([1, 2, 3]))).toEqual({
                isValid: false,
                refusalReason: 'malformedEncoding',
            });
            const accepted = opened.value.ingest(
                authenticatedComplaint.canonicalCarrierBytes,
            );
            expect(accepted.isValid).toBe(true);
            if (!accepted.isValid) {
                throw new Error(accepted.refusalReason);
            }
            expect(foundationBoardCandidateObjectHash(accepted.value)).toEqual(
                authenticatedComplaint.objectHash,
            );
            expect(opened.value.requireCompleteCarrierGraph()).toEqual({
                isValid: true,
                value: undefined,
            });
        } finally {
            opened.value.cancel();
        }

        expect(() =>
            foundationBoardCandidateObjectHash(
                Object.freeze({}) as Parameters<
                    typeof foundationBoardCandidateObjectHash
                >[0],
            ),
        ).toThrow('was not issued by this runtime');
    });

    it('derives the setup roster hash used by setup package verification', () => {
        const expectedSetupRosterHash = deriveCanonicalObjectHash({
            objectType: 'CollectiveBgvSetupRoster',
            rosterEntries: [
                {
                    objectType: 'CollectiveBgvSetupRosterEntry',
                    rosterPosition: 0,
                    trusteeIdentity: 'trustee-0',
                    signingPublicKeyHash: 'a'.repeat(128),
                },
                {
                    objectType: 'CollectiveBgvSetupRosterEntry',
                    rosterPosition: 1,
                    trusteeIdentity: 'trustee-1',
                    signingPublicKeyHash: 'b'.repeat(128),
                },
            ],
        });

        expect(
            deriveCollectiveBgvSetupRosterHash([
                {
                    rosterPosition: 1,
                    trusteeIdentity: 'trustee-1',
                    signingPublicKeyHash: 'b'.repeat(128),
                },
                {
                    rosterPosition: 0,
                    trusteeIdentity: 'trustee-0',
                    signingPublicKeyHash: 'a'.repeat(128),
                },
            ]),
        ).toBe(expectedSetupRosterHash);
    });
});

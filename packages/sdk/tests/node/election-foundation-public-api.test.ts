import { describe, expect, it } from 'vitest';

import * as publicApiRuntime from '../../dist/index.js';

import { deriveCanonicalObjectHash } from '#packages/crypto/src/index';
type DeriveCollectiveBgvSetupRosterHash = (
    entries: readonly Readonly<{
        readonly rosterPosition: number;
        readonly trusteeIdentity: string;
        readonly signingPublicKeyHash: string;
    }>[],
) => string;
const publicApiRuntimeRecord = publicApiRuntime as Record<string, unknown>;
const deriveCollectiveBgvSetupRosterHash =
    publicApiRuntimeRecord.deriveCollectiveBgvSetupRosterHash as DeriveCollectiveBgvSetupRosterHash;
const expectedPublicRuntimeExportNames = [
    'ThresholdParameterDerivationError',
    'deriveCollectiveBgvSetupRosterHash',
    'deriveFrozenRosterParameters',
    'derivePollSpecHash',
    'deriveThresholdParameters',
    'deriveThresholdParametersHash',
    'deriveValidatedFirstValidOrder',
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

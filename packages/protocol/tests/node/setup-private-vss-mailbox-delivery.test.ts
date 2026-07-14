import { deriveCanonicalObjectHash } from '@sealed-lattice/crypto';
import { describe, expect, it } from 'vitest';

import { createPrivateVssMailboxDeliverySet } from '#packages/protocol/src/index';
import {
    makeSetupContext,
    makeSetupFixtureHash,
} from '#tests/support/setup-fixtures';

const fixtureHash = makeSetupFixtureHash('setup-private-vss-mailbox-delivery');
const unavailableProofMessage =
    'Private VSS envelope generation requires one source-batched durable proof application per source trustee; per-recipient, per-limb proofs are not authorized.';

describe('private VSS mailbox delivery', () => {
    it('refuses per-recipient proof generation before consuming private capabilities', async () => {
        let privateCapabilityAccessCount = 0;
        const inaccessiblePrivateCapability = new Proxy(
            {},
            {
                get: () => {
                    privateCapabilityAccessCount += 1;
                    throw new Error(
                        'Fail-closed delivery must not access a private capability.',
                    );
                },
            },
        ) as never;
        let proofExportAttempted = false;
        let verificationAttempted = false;
        const setupContext = makeSetupContext(fixtureHash, 1);

        const createDelivery = () =>
            createPrivateVssMailboxDeliverySet({
                kernel: {
                    deriveCanonicalObjectHash: ({ value }) =>
                        deriveCanonicalObjectHash(value),
                    exportCanonicalProofMaterial: () => {
                        proofExportAttempted = true;
                        return Promise.resolve({
                            descriptorBytes: new Uint8Array([1]),
                        });
                    },
                    verifyPrivateVssShareEnvelope: () => {
                        verificationAttempted = true;
                        return {
                            isValid: true,
                            value: {
                                privateEnvelopeHash:
                                    fixtureHash('private-envelope'),
                                localVerificationRoot:
                                    fixtureHash('local-verification'),
                            },
                        };
                    },
                },
                mailboxKernel: inaccessiblePrivateCapability,
                mailboxOutboundCache: inaccessiblePrivateCapability,
                emitMailboxCiphertextChunk: inaccessiblePrivateCapability,
                foundationContext: {
                    suiteId: fixtureHash('suite'),
                    ceremonyContextHash: fixtureHash('ceremony-context'),
                    actionContextHash: fixtureHash('action-context'),
                },
                setupContext,
                publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
                vssCoefficientCommitmentRoot: fixtureHash(
                    'vss-coefficient-commitment',
                ),
                qSharePrimes: [65_537],
                ringDegree: 2,
                participantCount: 1,
                sourceTrusteeContributionStates: [
                    {
                        sourceTrusteeIdentity: 'trustee-0',
                        sourceParticipantId: fixtureHash('source-participant'),
                        sourceTrusteeRosterPosition: 0,
                        sourceSigningCapability: inaccessiblePrivateCapability,
                        sourceVerificationKey: inaccessiblePrivateCapability,
                        sourceActionRandomnessCapability:
                            inaccessiblePrivateCapability,
                        sourceTrusteeCommitmentRoot: fixtureHash(
                            'source-trustee-root',
                        ),
                        sourceTrusteeCoefficientCommitmentRecord: {},
                        sourceTrusteeCoefficientCommitmentMaterialRecords: [],
                        coefficientOpenings: [
                            {
                                rnsLimbIndex: 0,
                                rnsPrime: 65_537,
                                shamirCoefficientIndex: 0,
                                commitmentRoot: fixtureHash('coefficient-root'),
                                coefficientMessage: [1, 2],
                                randomnessByColumn: [[0, 1]],
                            },
                        ],
                    },
                ],
                recipients: [
                    {
                        recipientIdentity: 'trustee-0',
                        recipientParticipantId:
                            fixtureHash('source-participant'),
                        recipientRosterPosition: 0,
                        mailboxEncapsulationKey: new Uint8Array([1]),
                    },
                ],
            });

        await expect(createDelivery()).rejects.toThrow(unavailableProofMessage);
        await expect(createDelivery()).rejects.toThrow(unavailableProofMessage);
        expect(privateCapabilityAccessCount).toBe(0);
        expect(proofExportAttempted).toBe(false);
        expect(verificationAttempted).toBe(false);
    });
});

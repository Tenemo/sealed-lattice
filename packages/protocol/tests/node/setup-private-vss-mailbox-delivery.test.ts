import { deriveProtocolHash } from '@sealed-lattice/crypto';
import { describe, expect, it } from 'vitest';

import { createPrivateVssMailboxDeliverySet } from '#packages/protocol/src/index';

const fixtureHash = (label: string): string =>
    deriveProtocolHash('ActionContextHash', {
        fixture: 'setup-private-vss-mailbox-delivery',
        label,
    });

const setupContext = {
    ceremonyId: 'ceremony-1',
    manifestHash: fixtureHash('manifest'),
    rosterHash: fixtureHash('roster'),
    setupProfileHash: fixtureHash('setup-profile'),
    qShareHash: fixtureHash('q-share'),
    carryAwareVssShareRelationProfileHash: fixtureHash('carry-aware'),
    commitmentProfileHash: fixtureHash('commitment-profile'),
    setupEpoch: 'setup-epoch-1',
} as const;

describe('private VSS mailbox delivery', () => {
    it('refuses to build delivery envelopes without a private share proof factory', async () => {
        await expect(
            createPrivateVssMailboxDeliverySet({
                kernel: {
                    deriveProtocolHash: ({ namespace, value }) =>
                        deriveProtocolHash(namespace, value),
                    verifyPrivateVssShareEnvelope: () => {
                        throw new Error(
                            'local verifier must not be reached without proof generation.',
                        );
                    },
                },
                setupContext,
                phaseOrderHash: fixtureHash('phase-order'),
                publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
                vssCoefficientCommitmentRoot: fixtureHash(
                    'vss-coefficient-commitment',
                ),
                qSharePrimes: [65_537],
                ringDegree: 2,
                participantCount: 1,
                deliveryPhaseNumber: 6,
                verificationPhaseNumber: 7,
                dealerContributionStates: [
                    {
                        dealerIdentity: 'trustee-0',
                        dealerRosterPosition: 0,
                        dealerCommitmentRoot: fixtureHash('dealer-root'),
                        dealerCoefficientCommitmentRecord: {},
                        dealerCoefficientCommitmentMaterialRecords: [],
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
                        recipientRosterPosition: 0,
                        mailboxPublicKeyBytesHex: '00',
                    },
                ],
            }),
        ).rejects.toThrow(/privateVssShareProof generation/u);
    });
});

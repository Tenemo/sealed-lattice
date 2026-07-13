import {
    createPrivateVssMailboxKeyPair,
    deriveCanonicalObjectHash,
} from '@sealed-lattice/crypto';
import { describe, expect, it } from 'vitest';

import { createPrivateVssMailboxDeliverySet } from '#packages/protocol/src/index';
import { canonicalStreamDescriptorFixture } from '#tests/support/canonical-stream-descriptor-fixture';
import { withDeterministicWebCryptoRandomness } from '#tests/support/deterministic-web-crypto-randomness';
import {
    makeSetupContext,
    makeSetupFixtureHash,
} from '#tests/support/setup-fixtures';

const fixtureHash = makeSetupFixtureHash('setup-private-vss-mailbox-delivery');

const setupContext = makeSetupContext(fixtureHash);

describe('private VSS mailbox delivery', () => {
    it('transports private VSS proof material under its canonical descriptor and semantic root', async () => {
        const proofBytesHash = fixtureHash('proof-bytes');
        const descriptorBytes = canonicalStreamDescriptorFixture(4, 9, 8);
        const expectedTransportedMaterialRoot = deriveCanonicalObjectHash({
            objectType: 'PrivateVssShareTransportedSuccinctProofMaterial',
            statementHash: fixtureHash('statement-hash'),
            proofBytesHash,
        });
        let observedPrivateEnvelope: Record<string, unknown> | undefined;
        let observedTransportedProofMaterial:
            | Record<string, unknown>
            | undefined;
        const mailboxKeyPair = createPrivateVssMailboxKeyPair(
            fixtureHash('mailbox-key'),
        );

        const deliverySet = await withDeterministicWebCryptoRandomness(
            [
                fixtureHash('proof-randomness-seed'),
                fixtureHash('proof-randomness-nonce'),
                fixtureHash('mailbox-encapsulation-randomness').slice(0, 64),
                fixtureHash('mailbox-aead-nonce').slice(0, 24),
            ],
            () =>
                createPrivateVssMailboxDeliverySet({
                    kernel: {
                        deriveCanonicalObjectHash: ({ value }) =>
                            deriveCanonicalObjectHash(value),
                        generatePrivateVssShareProof: () => ({
                            privateVssShareProof: {
                                objectType: 'PrivateVssShareProof',
                                statementHash: fixtureHash('statement-hash'),
                                proofBytesHash,
                                proofMaterialRoot:
                                    expectedTransportedMaterialRoot,
                            },
                        }),
                        exportCanonicalProofMaterial: () =>
                            Promise.resolve({ descriptorBytes }),
                        verifyPrivateVssShareEnvelope: (input) => {
                            observedPrivateEnvelope =
                                input.privateEnvelope as Record<
                                    string,
                                    unknown
                                >;
                            observedTransportedProofMaterial =
                                input.transportedPrivateVssShareProofMaterial as
                                    | Record<string, unknown>
                                    | undefined;

                            return {
                                isValid: true,
                                privateEnvelopeHash: deriveCanonicalObjectHash(
                                    input.privateEnvelope,
                                ),
                                localVerificationRoot:
                                    fixtureHash('local-verification'),
                                refusedObjects: [],
                            };
                        },
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
                            sourceTrusteeRosterPosition: 0,
                            sourceTrusteeCommitmentRoot: fixtureHash(
                                'source-trustee-root',
                            ),
                            sourceTrusteeCoefficientCommitmentRecord: {},
                            sourceTrusteeCoefficientCommitmentMaterialRecords:
                                [],
                            coefficientOpenings: [
                                {
                                    rnsLimbIndex: 0,
                                    rnsPrime: 65_537,
                                    shamirCoefficientIndex: 0,
                                    commitmentRoot:
                                        fixtureHash('coefficient-root'),
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
                            mailboxPublicKeyBytesHex:
                                mailboxKeyPair.publicKeyBytesHex,
                        },
                    ],
                }),
        );

        expect(observedPrivateEnvelope).toBeDefined();
        const limbOpening = (
            observedPrivateEnvelope?.rnsShareOpenings as Record<
                string,
                unknown
            >[]
        )[0];
        const transportedProofRecord =
            limbOpening.privateVssShareProof as Record<string, unknown>;
        expect(transportedProofRecord.proofMaterialRoot).toBe(
            expectedTransportedMaterialRoot,
        );
        expect(observedTransportedProofMaterial).toBeDefined();
        expect(observedTransportedProofMaterial?.objectType).toBe(
            'SetupTransportedPrivateVssShareProofMaterialSet',
        );
        const proofMaterials =
            observedTransportedProofMaterial?.proofMaterials as Record<
                string,
                unknown
            >[];
        expect(proofMaterials).toHaveLength(1);
        expect(proofMaterials[0]).toMatchObject({
            objectType: 'SetupTransportedPrivateVssShareProofMaterial',
            proofMaterialRoot: transportedProofRecord.proofMaterialRoot,
        });
        const returnedProofMaterial =
            deliverySet.envelopeReferences[0]
                .transportedPrivateVssShareProofMaterial?.proofMaterials[0];
        expect(returnedProofMaterial).toMatchObject({
            objectType: 'SetupTransportedPrivateVssShareProofMaterial',
            proofMaterialRoot: transportedProofRecord.proofMaterialRoot,
            descriptorBytes,
        });
        expect(returnedProofMaterial?.descriptorBytes).not.toBe(
            descriptorBytes,
        );
    });
});

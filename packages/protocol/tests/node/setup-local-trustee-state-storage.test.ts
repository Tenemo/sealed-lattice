import {
    decryptLocalTrusteeSetupSealedMaterial,
    deriveProtocolHash,
    encryptLocalTrusteeSetupSealedMaterial,
} from '@sealed-lattice/crypto';
import { describe, expect, it } from 'vitest';

import {
    aggregateCompactVssThresholdShareCommitments,
    createCompactVssCoefficientCommitmentSet,
    createCompactVssRecipientShareCommitmentBundle,
    createCompactVssShareLinkageStatement,
} from '#packages/protocol/src/setup/compact-vss-commitments';
import {
    createEncryptedLocalTrusteeSetupStateFromVerifiedShares,
    decryptLocalTrusteeSetupState,
    encryptLocalTrusteeSetupState,
    type LocalTrusteeSetupStateEncryptionInput,
} from '#packages/protocol/src/setup/local-trustee-setup-state';
import {
    makeSetupContext,
    makeSetupFixtureHash,
} from '#tests/support/setup-fixtures';

const fixtureHash = makeSetupFixtureHash('setup-local-trustee-state-storage');

const setupContext = makeSetupContext(fixtureHash);

const storageInputBase = {
    setupContext,
    trusteeIdentity: 'trustee-3',
    trusteeRosterPosition: 3,
    thresholdShareCommitmentRecipientRoot: fixtureHash(
        'threshold-share-commitment-recipient',
    ),
    issuedVssAcceptanceRoot: fixtureHash('issued-vss-acceptance'),
    issuedVssComplaintRoots: [fixtureHash('issued-vss-complaint')],
    storageKeyBytesHex: '11'.repeat(32),
    aeadNonceBytesHex: '22'.repeat(12),
} as const;

type LocalStatePlaintextFixture = Readonly<{
    readonly plaintext: LocalTrusteeSetupStateEncryptionInput['localStatePlaintext'];
    readonly storageInput: Omit<
        LocalTrusteeSetupStateEncryptionInput,
        'localStatePlaintext'
    >;
}>;

type GeneratedLocalStateFixtureInput = Parameters<
    typeof createEncryptedLocalTrusteeSetupStateFromVerifiedShares
>[0];

type CompactTargetProofWitnessFixture = NonNullable<
    GeneratedLocalStateFixtureInput['compactVssTargetProofWitness']
>;

const shareValuesToLittleEndian48Hex = (
    values: readonly number[],
    rnsPrime: number,
): string => {
    const bytes = new Uint8Array(values.length * 6);
    values.forEach((value, valueIndex) => {
        if (!Number.isSafeInteger(value) || value < 0 || value >= rnsPrime) {
            throw new TypeError('fixture share value must be below rnsPrime.');
        }
        let remainingValue = BigInt(value);
        for (let byteIndex = 0; byteIndex < 6; byteIndex += 1) {
            bytes[valueIndex * 6 + byteIndex] = Number(remainingValue & 0xffn);
            remainingValue >>= 8n;
        }
    });

    return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join(
        '',
    );
};

const localStatePlaintext = async (): Promise<LocalStatePlaintextFixture> => {
    const sealedAggregateThresholdShare =
        await encryptLocalTrusteeSetupSealedMaterial({
            materialClass: 'aggregate-threshold-share-sealed',
            materialPlaintext: {
                objectType: 'LocalTrusteeAggregateThresholdShareMaterial',
                objectVersion: 1,
                trusteeIdentity: storageInputBase.trusteeIdentity,
                trusteeRosterPosition: storageInputBase.trusteeRosterPosition,
                thresholdShareCommitmentRecipientRoot:
                    storageInputBase.thresholdShareCommitmentRecipientRoot,
                shareValues: [7, 8, 9],
            },
            setupContext,
            trusteeIdentity: storageInputBase.trusteeIdentity,
            trusteeRosterPosition: storageInputBase.trusteeRosterPosition,
            thresholdShareCommitmentRecipientRoot:
                storageInputBase.thresholdShareCommitmentRecipientRoot,
            storageKeyBytesHex: storageInputBase.storageKeyBytesHex,
            aeadNonceBytesHex: '33'.repeat(12),
        });
    const sealedTargetDecryptionProofWitness =
        await encryptLocalTrusteeSetupSealedMaterial({
            materialClass: 'target-decryption-proof-witness-sealed',
            materialPlaintext: {
                objectType: 'LocalTrusteeTargetDecryptionProofWitnessMaterial',
                objectVersion: 1,
                trusteeIdentity: storageInputBase.trusteeIdentity,
                trusteeRosterPosition: storageInputBase.trusteeRosterPosition,
                thresholdShareCommitmentRecipientRoot:
                    storageInputBase.thresholdShareCommitmentRecipientRoot,
                aggregateThresholdShareRoot:
                    sealedAggregateThresholdShare.materialRoot,
            },
            setupContext,
            trusteeIdentity: storageInputBase.trusteeIdentity,
            trusteeRosterPosition: storageInputBase.trusteeRosterPosition,
            thresholdShareCommitmentRecipientRoot:
                storageInputBase.thresholdShareCommitmentRecipientRoot,
            storageKeyBytesHex: storageInputBase.storageKeyBytesHex,
            aeadNonceBytesHex: '44'.repeat(12),
        });
    const storageInput = {
        ...storageInputBase,
        aggregateThresholdShareRoot: sealedAggregateThresholdShare.materialRoot,
        targetDecryptionProofWitnessRoot:
            sealedTargetDecryptionProofWitness.materialRoot,
    } as const;
    const plaintext = {
        objectType: 'LocalTrusteeSetupStateSealedPayload',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        ceremonyId: setupContext.ceremonyId,
        manifestHash: setupContext.manifestHash,
        rosterHash: setupContext.rosterHash,
        setupEpoch: setupContext.setupEpoch,
        trusteeIdentity: storageInputBase.trusteeIdentity,
        trusteeRosterPosition: storageInputBase.trusteeRosterPosition,
        deviceEpoch: 0,
        thresholdShareCommitmentRecipientRoot:
            storageInput.thresholdShareCommitmentRecipientRoot,
        sealedAggregateThresholdShare:
            sealedAggregateThresholdShare.sealedMaterial,
        sealedTargetDecryptionProofWitness:
            sealedTargetDecryptionProofWitness.sealedMaterial,
        issuedVssAcceptanceRoots: [storageInput.issuedVssAcceptanceRoot],
        issuedVssComplaintRoots: storageInput.issuedVssComplaintRoots,
    } as const;

    return { plaintext, storageInput };
};

const generatedLocalStateInput = (
    compactVssRecipientShareOpeningCredential?: unknown,
    deliveredShareValues: readonly number[] = [7, 11, 13, 17],
): GeneratedLocalStateFixtureInput => {
    const trusteeIdentity = 'trustee-0';
    const trusteeRosterPosition = 0;
    const sourceTrusteeCommitmentRoot = fixtureHash(
        'compact-source-trustee-root',
    );
    const publicMatrixSeedHash = fixtureHash('compact-public-matrix-seed');
    const privateVssEnvelopeCommitmentRoot = fixtureHash(
        'compact-private-envelope-set',
    );
    const privateEnvelope = {
        objectType: 'PrivateVssShareEnvelope',
        objectVersion: 1,
        ...setupContext,
        publicMatrixSeedHash,
        sourceTrusteeIdentity: trusteeIdentity,
        sourceTrusteeRosterPosition: trusteeRosterPosition,
        recipientIdentity: trusteeIdentity,
        recipientRosterPosition: trusteeRosterPosition,
        sourceTrusteeCommitmentRoot,
        rnsShareOpenings: [
            {
                objectType: 'PrivateVssShareLimbOpening',
                objectVersion: 1,
                rnsLimbIndex: 0,
                rnsPrime: 65_537,
                shareValuesLittleEndian48Hex: shareValuesToLittleEndian48Hex(
                    deliveredShareValues,
                    65_537,
                ),
                ...(compactVssRecipientShareOpeningCredential === undefined
                    ? {}
                    : { compactVssRecipientShareOpeningCredential }),
            },
        ],
    } as const;
    const privateEnvelopeHash = deriveProtocolHash(
        'PrivateVssShareEnvelopeHash',
        privateEnvelope,
    );

    return {
        setupContext,
        trusteeIdentity,
        trusteeRosterPosition,
        deviceEpoch: 4,
        thresholdShareCommitments: {
            objectType: 'ThresholdShareCommitmentSet',
            objectVersion: 1,
            ...setupContext,
            recipientRecords: [
                {
                    objectType: 'ThresholdShareCommitmentRecipient',
                    objectVersion: 1,
                    recipientIdentity: trusteeIdentity,
                    recipientRosterPosition: trusteeRosterPosition,
                    recipientCommitmentRoot: fixtureHash(
                        'compact-threshold-recipient',
                    ),
                },
            ],
        },
        privateVssEnvelopeCommitments: {
            objectType: 'PrivateVssEnvelopeCommitmentSet',
            objectVersion: 1,
            ...setupContext,
            participantCount: 1,
            privateVssEnvelopeCommitmentRoot,
            envelopeReferences: [
                {
                    objectType: 'PrivateVssEnvelopeCommitment',
                    objectVersion: 1,
                    ...setupContext,
                    sourceTrusteeIdentity: trusteeIdentity,
                    sourceTrusteeRosterPosition: trusteeRosterPosition,
                    recipientIdentity: trusteeIdentity,
                    recipientRosterPosition: trusteeRosterPosition,
                    sourceTrusteeCommitmentRoot,
                    privateEnvelopeCommitmentRoot: fixtureHash(
                        'compact-private-envelope-commitment',
                    ),
                    encryptedEnvelopeHash: fixtureHash(
                        'compact-encrypted-envelope',
                    ),
                    privateEnvelopeHash,
                    localVerificationRoot: fixtureHash(
                        'compact-local-verification',
                    ),
                },
            ],
        },
        verifiedPrivateVssShareEnvelopes: [privateEnvelope],
        vssShareAcceptances: {
            objectType: 'VssShareAcceptanceSet',
            objectVersion: 1,
            ...setupContext,
            acceptanceRecords: [
                {
                    objectType: 'VssShareAcceptance',
                    objectVersion: 1,
                    ...setupContext,
                    sourceTrusteeIdentity: trusteeIdentity,
                    sourceTrusteeRosterPosition: trusteeRosterPosition,
                    recipientIdentity: trusteeIdentity,
                    recipientRosterPosition: trusteeRosterPosition,
                    privateVssEnvelopeCommitmentRoot,
                    privateEnvelopeHash,
                    localVerificationRoot: fixtureHash(
                        'compact-local-verification',
                    ),
                    acceptanceRoot: fixtureHash('compact-acceptance-root'),
                },
            ],
        },
        storageKeyBytesHex: '51'.repeat(32),
        localStateAeadNonceBytesHex: '52'.repeat(12),
        sealedAggregateThresholdShareAeadNonceBytesHex: '53'.repeat(12),
        sealedTargetDecryptionProofWitnessAeadNonceBytesHex: '54'.repeat(12),
    } as const;
};

const compactTargetProofWitness = (): CompactTargetProofWitnessFixture => {
    const publicMatrixSeedHash = fixtureHash('compact-public-matrix-seed');
    const sourceTrusteeOpeningStates = [
        {
            sourceTrusteeIdentity: 'trustee-0',
            sourceTrusteeRosterPosition: 0,
            coefficientOpenings: [
                {
                    rnsLimbIndex: 0,
                    rnsPrime: 65_537,
                    shamirCoefficientIndex: 0,
                    coefficientMessage: [7, 11, 13, 17],
                    randomnessByColumn: [],
                },
            ],
        },
    ];
    const recipientTrustees = [
        {
            trusteeIdentity: 'trustee-0',
            trusteeRosterPosition: 0,
        },
    ];
    const coefficientCommitmentSet = createCompactVssCoefficientCommitmentSet({
        setupContext,
        publicMatrixSeedHash,
        participantCount: 1,
        qSharePrimes: [65_537],
        ringDegree: 4,
        thresholdDegree: 1,
        sourceTrusteeOpeningStates,
        coefficientOpeningRandomness: ({ ringDegree }) => [
            Array.from({ length: ringDegree }, (_unused, index) =>
                index % 2 === 0 ? 1 : 0,
            ),
            Array.from({ length: ringDegree }, (_unused, index) =>
                index % 2 === 0 ? -1 : 1,
            ),
        ],
    });
    const recipientShareBundle = createCompactVssRecipientShareCommitmentBundle(
        {
            setupContext,
            publicMatrixSeedHash,
            participantCount: 1,
            qSharePrimes: [65_537],
            ringDegree: 4,
            thresholdDegree: 1,
            sourceTrusteeOpeningStates,
            recipientTrustees,
            shareOpeningRandomness: ({ ringDegree }) => [
                Array.from({ length: ringDegree }, (_unused, index) =>
                    index % 2 === 0 ? 1 : -1,
                ),
                Array.from({ length: ringDegree }, (_unused, index) =>
                    index % 2 === 0 ? 0 : 1,
                ),
            ],
        },
    );
    const aggregateBundle = aggregateCompactVssThresholdShareCommitments({
        setupContext,
        publicMatrixSeedHash,
        participantCount: 1,
        qSharePrimes: [65_537],
        ringDegree: 4,
        recipientTrustees,
        recipientShareOpeningCredentials:
            recipientShareBundle.recipientShareOpeningCredentials,
    });
    const shareLinkageStatement = createCompactVssShareLinkageStatement({
        setupContext,
        publicMatrixSeedHash,
        targetBasisHash: fixtureHash('compact-target-basis'),
        coefficientCommitmentSet,
        recipientShareCommitmentSet:
            recipientShareBundle.recipientShareCommitmentSet,
        aggregateThresholdCommitmentSet:
            aggregateBundle.aggregateThresholdCommitmentSet,
    });

    return {
        coefficientCommitmentSet,
        recipientShareCommitmentSet:
            recipientShareBundle.recipientShareCommitmentSet,
        aggregateThresholdCommitmentSet:
            aggregateBundle.aggregateThresholdCommitmentSet,
        aggregateThresholdOpeningCredentials:
            aggregateBundle.aggregateThresholdOpeningCredentials,
        recipientShareOpeningCredentials:
            recipientShareBundle.recipientShareOpeningCredentials,
        shareLinkageStatement,
    } as const;
};

const rebindCompactVssShareLinkageStatementRoot = (
    statement: CompactTargetProofWitnessFixture['shareLinkageStatement'],
): CompactTargetProofWitnessFixture['shareLinkageStatement'] => {
    const { statementRoot: _statementRoot, ...statementWithoutRoot } =
        statement;

    return {
        ...statement,
        statementRoot: deriveProtocolHash(
            'SetupProofRecordBindingHash',
            statementWithoutRoot,
        ),
    };
};

const rebindCompactVssSourceStatementRoot = (
    sourceStatement: CompactTargetProofWitnessFixture['shareLinkageStatement']['sourceStatementRecords'][number],
): CompactTargetProofWitnessFixture['shareLinkageStatement']['sourceStatementRecords'][number] => {
    const {
        sourceStatementRoot: _sourceStatementRoot,
        ...sourceStatementWithoutRoot
    } = sourceStatement;

    return {
        ...sourceStatement,
        sourceStatementRoot: deriveProtocolHash(
            'SetupProofRecordBindingHash',
            sourceStatementWithoutRoot,
        ),
    };
};

describe('local trustee setup state storage', () => {
    it('encrypts and restores protocol-built roots-only local state', async () => {
        const { plaintext, storageInput } = await localStatePlaintext();

        const encryptedState = await encryptLocalTrusteeSetupState({
            ...storageInput,
            localStatePlaintext: plaintext,
        });
        const decryptedState = await decryptLocalTrusteeSetupState({
            encryptedLocalState: encryptedState.encryptedLocalState,
            sealedAggregateThresholdShare:
                plaintext.sealedAggregateThresholdShare,
            sealedTargetDecryptionProofWitness:
                plaintext.sealedTargetDecryptionProofWitness,
            expectedLocalStateRoot:
                encryptedState.localStateCommitment.localStateRoot,
            setupContext,
            storageKeyBytesHex: storageInput.storageKeyBytesHex,
        });

        expect(encryptedState.encryptedLocalState.localStateRoot).toBe(
            encryptedState.localStateCommitment.localStateRoot,
        );
        expect(
            encryptedState.encryptedLocalState.storageAad.localStateCommitment,
        ).toEqual(encryptedState.localStateCommitment);
        expect(decryptedState).toMatchObject({
            localStatePlaintext: plaintext,
            localStatePlaintextHash: encryptedState.localStatePlaintextHash,
            storageAadHash: encryptedState.storageAadHash,
        });
    });

    it('rejects unknown fields and setup-context rebinding', async () => {
        const { plaintext, storageInput } = await localStatePlaintext();

        await expect(
            encryptLocalTrusteeSetupState({
                ...storageInput,
                localStatePlaintext: {
                    ...plaintext,
                    unrecognizedAggregateShareCopy: [1, 2, 3],
                },
            }),
        ).rejects.toThrow(/not allowed by the local trustee state schema/u);

        const encryptedState = await encryptLocalTrusteeSetupState({
            ...storageInput,
            localStatePlaintext: plaintext,
        });

        await expect(
            decryptLocalTrusteeSetupState({
                encryptedLocalState: encryptedState.encryptedLocalState,
                sealedAggregateThresholdShare:
                    plaintext.sealedAggregateThresholdShare,
                sealedTargetDecryptionProofWitness:
                    plaintext.sealedTargetDecryptionProofWitness,
                expectedLocalStateRoot:
                    encryptedState.localStateCommitment.localStateRoot,
                setupContext: {
                    ...setupContext,
                    setupEpoch: 'setup-epoch-2',
                },
                storageKeyBytesHex: storageInput.storageKeyBytesHex,
            }),
        ).rejects.toThrow(/storageAad/u);
    });

    it('seals compact aggregate openings after checking aggregate share parity', async () => {
        const generatedInput = generatedLocalStateInput();
        const baselineState =
            await createEncryptedLocalTrusteeSetupStateFromVerifiedShares(
                generatedInput,
            );
        const compactWitness = compactTargetProofWitness();
        const compactState =
            await createEncryptedLocalTrusteeSetupStateFromVerifiedShares({
                ...generatedInput,
                compactVssTargetProofWitness: {
                    ...compactWitness,
                    targetDecryptionRnsLimbCount: 1,
                },
            });

        expect(
            compactState.localStateCommitment.aggregateThresholdShareRoot,
        ).toBe(baselineState.localStateCommitment.aggregateThresholdShareRoot);
        expect(
            compactState.localStateCommitment.targetDecryptionProofWitnessRoot,
        ).not.toBe(
            baselineState.localStateCommitment.targetDecryptionProofWitnessRoot,
        );
        expect(
            compactState.sealedTargetDecryptionProofWitness.encryptedMaterial
                .plaintextByteLength,
        ).toBeGreaterThan(
            baselineState.sealedTargetDecryptionProofWitness.encryptedMaterial
                .plaintextByteLength,
        );
        const restoredCompactWitness =
            await decryptLocalTrusteeSetupSealedMaterial({
                sealedMaterial: compactState.sealedTargetDecryptionProofWitness,
                expectedMaterialClass: 'target-decryption-proof-witness-sealed',
                expectedMaterialRoot:
                    compactState.localStateCommitment
                        .targetDecryptionProofWitnessRoot,
                setupContext,
                localStateCommitment: compactState.localStateCommitment,
                storageKeyBytesHex: generatedInput.storageKeyBytesHex,
            });
        expect(restoredCompactWitness.materialPlaintext).toMatchObject({
            objectType: 'LocalTrusteeTargetDecryptionProofWitnessMaterial',
            objectVersion: 1,
            trusteeIdentity: generatedInput.trusteeIdentity,
            trusteeRosterPosition: generatedInput.trusteeRosterPosition,
            thresholdShareCommitmentRecipientRoot:
                compactState.localStateCommitment
                    .thresholdShareCommitmentRecipientRoot,
            aggregateThresholdShareRoot:
                compactState.localStateCommitment.aggregateThresholdShareRoot,
            compactAggregateOpening: {
                objectType: 'LocalTrusteeCompactVssAggregateOpeningWitness',
                objectVersion: 1,
                publicMatrixSeedHash:
                    compactWitness.aggregateThresholdCommitmentSet
                        .publicMatrixSeedHash,
                targetBasisHash:
                    compactWitness.shareLinkageStatement.targetBasisHash,
                shareLinkageStatementRoot:
                    compactWitness.shareLinkageStatement.statementRoot,
                aggregateThresholdCommitmentRoot:
                    compactWitness.aggregateThresholdCommitmentSet
                        .aggregateThresholdCommitmentRoot,
                compactAggregateOpeningCredentials: [
                    expect.objectContaining({
                        objectType:
                            'LocalTrusteeCompactVssAggregateOpeningCredential',
                        recipientIdentity: generatedInput.trusteeIdentity,
                        recipientRosterPosition:
                            generatedInput.trusteeRosterPosition,
                        rnsLimbIndex: 0,
                        rnsPrime: 65_537,
                    }),
                ],
            },
        });
        const restoredCompactWitnessMaterial =
            restoredCompactWitness.materialPlaintext as {
                readonly compactAggregateOpening: {
                    readonly compactAggregateOpeningCredentials: readonly unknown[];
                };
            };
        expect(
            restoredCompactWitnessMaterial.compactAggregateOpening
                .compactAggregateOpeningCredentials,
        ).toHaveLength(1);
        await expect(
            createEncryptedLocalTrusteeSetupStateFromVerifiedShares({
                ...generatedInput,
                compactVssTargetProofWitness: {
                    ...compactWitness,
                    targetDecryptionRnsLimbCount: 2,
                },
            }),
        ).rejects.toThrow(/targetDecryptionRnsLimbCount/u);
        await expect(
            decryptLocalTrusteeSetupSealedMaterial({
                sealedMaterial: compactState.sealedTargetDecryptionProofWitness,
                expectedMaterialClass: 'target-decryption-proof-witness-sealed',
                expectedMaterialRoot:
                    compactState.localStateCommitment
                        .aggregateThresholdShareRoot,
                setupContext,
                localStateCommitment: compactState.localStateCommitment,
                storageKeyBytesHex: generatedInput.storageKeyBytesHex,
            }),
        ).rejects.toThrow(/materialRoot/u);

        const aggregateThresholdOpeningCredentials =
            compactWitness.aggregateThresholdOpeningCredentials;
        if (aggregateThresholdOpeningCredentials?.[0] === undefined) {
            throw new Error(
                'compact VSS test fixture did not create a credential.',
            );
        }
        const firstCredential = aggregateThresholdOpeningCredentials[0];

        await expect(
            createEncryptedLocalTrusteeSetupStateFromVerifiedShares({
                ...generatedLocalStateInput(),
                compactVssTargetProofWitness: {
                    ...compactWitness,
                    aggregateThresholdOpeningCredentials: [
                        {
                            ...firstCredential,
                            aggregateShareValues: [8, 11, 13, 17],
                            aggregateCommitmentMessageValues: [8, 11, 13, 17],
                        },
                    ],
                },
            }),
        ).rejects.toThrow(/aggregate threshold share material/u);

        const firstAggregateRecord =
            compactWitness.aggregateThresholdCommitmentSet.recipientRecords[0];
        if (firstAggregateRecord === undefined) {
            throw new Error(
                'compact VSS test fixture did not create an aggregate record.',
            );
        }
        await expect(
            createEncryptedLocalTrusteeSetupStateFromVerifiedShares({
                ...generatedLocalStateInput(),
                compactVssTargetProofWitness: {
                    ...compactWitness,
                    aggregateThresholdCommitmentSet: {
                        ...compactWitness.aggregateThresholdCommitmentSet,
                        recipientRecords: [
                            {
                                ...firstAggregateRecord,
                                aggregateCommitmentRoot: fixtureHash(
                                    'tampered-aggregate-record',
                                ),
                            },
                        ],
                    },
                },
            }),
        ).rejects.toThrow(/commitment canonical root must match/u);

        await expect(
            createEncryptedLocalTrusteeSetupStateFromVerifiedShares({
                ...generatedLocalStateInput(),
                compactVssTargetProofWitness: {
                    ...compactWitness,
                    aggregateThresholdCommitmentSet: {
                        ...compactWitness.aggregateThresholdCommitmentSet,
                        aggregateThresholdCommitmentRoot: fixtureHash(
                            'tampered-aggregate-set',
                        ),
                    },
                },
            }),
        ).rejects.toThrow(
            /aggregate threshold commitment set root does not match/u,
        );
    });

    it('derives sealed compact aggregate openings from credentials delivered in private envelopes', async () => {
        const compactWitness = compactTargetProofWitness();
        const recipientShareOpeningCredentials =
            compactWitness.recipientShareOpeningCredentials;
        if (recipientShareOpeningCredentials?.[0] === undefined) {
            throw new Error(
                'compact VSS test fixture did not create a recipient credential.',
            );
        }
        const firstRecipientCredential = recipientShareOpeningCredentials[0];

        const deliveredState =
            await createEncryptedLocalTrusteeSetupStateFromVerifiedShares({
                ...generatedLocalStateInput(firstRecipientCredential),
                compactVssTargetProofWitness: {
                    aggregateThresholdCommitmentSet:
                        compactWitness.aggregateThresholdCommitmentSet,
                    shareLinkageStatement: compactWitness.shareLinkageStatement,
                },
            });

        expect(
            deliveredState.sealedTargetDecryptionProofWitness.encryptedMaterial
                .plaintextByteLength,
        ).toBeGreaterThan(1_000);

        await expect(
            createEncryptedLocalTrusteeSetupStateFromVerifiedShares({
                ...generatedLocalStateInput(
                    firstRecipientCredential,
                    [8, 11, 13, 17],
                ),
                compactVssTargetProofWitness: {
                    aggregateThresholdCommitmentSet:
                        compactWitness.aggregateThresholdCommitmentSet,
                    shareLinkageStatement: compactWitness.shareLinkageStatement,
                },
            }),
        ).rejects.toThrow(/recipient share opening credential does not open/u);
    });

    it('rejects public compact linkage material without recipient-owned openings', async () => {
        const compactWitness = compactTargetProofWitness();

        await expect(
            createEncryptedLocalTrusteeSetupStateFromVerifiedShares({
                ...generatedLocalStateInput(),
                compactVssTargetProofWitness: {
                    aggregateThresholdCommitmentSet:
                        compactWitness.aggregateThresholdCommitmentSet,
                    shareLinkageStatement: compactWitness.shareLinkageStatement,
                },
            }),
        ).rejects.toThrow(
            /recipient share opening credentials must cover every source trustee/u,
        );
    });

    it('rejects local compact witness sealing when linkage roots disagree with supplied evidence', async () => {
        const compactWitness = compactTargetProofWitness();
        const forgedShareLinkageStatement =
            rebindCompactVssShareLinkageStatementRoot({
                ...compactWitness.shareLinkageStatement,
                sourceStatementRecords:
                    compactWitness.shareLinkageStatement.sourceStatementRecords.map(
                        (sourceStatement, sourceStatementIndex) =>
                            sourceStatementIndex === 0
                                ? rebindCompactVssSourceStatementRoot({
                                      ...sourceStatement,
                                      sourceRecipientShareCommitmentRoot:
                                          fixtureHash(
                                              'forged-local-state-source-recipient-root',
                                          ),
                                  })
                                : sourceStatement,
                    ),
            });

        await expect(
            createEncryptedLocalTrusteeSetupStateFromVerifiedShares({
                ...generatedLocalStateInput(),
                compactVssTargetProofWitness: {
                    ...compactWitness,
                    shareLinkageStatement: forgedShareLinkageStatement,
                },
            }),
        ).rejects.toThrow(/evidence source roots/u);
    });
});

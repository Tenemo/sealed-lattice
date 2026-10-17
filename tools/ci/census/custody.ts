import { compileFirstOracleCheckpointCensus } from '#tests/first-oracle-checkpoint-model.js';
import { compileParticipantBallotCustody } from '#tests/participant-ballot-custody-model.js';
import { compileParticipantCloseCustody } from '#tests/participant-close-custody-model.js';
import {
    compileContributionProofStorage,
    compileParticipantCustodyCensus,
    compileParticipantVaultKeyClasses,
} from '#tests/participant-custody-model.js';
import { compileParticipantReleaseCustody } from '#tests/participant-release-custody-model.js';
import {
    completionProfile,
    completionProfileCounts,
    deriveSupportedProfile,
    largestSupportedProfile,
} from '#tests/supported-profile-model.js';
import { compileSupportedThresholdCompletionProfiles } from '#tests/threshold-completion-model.js';
import { formatCount, table } from '#tools/ci/census/format.js';

export const renderParticipantBallotCustody = (): string[] => {
    const completion = completionProfile();
    const participantBallotCustody =
        compileParticipantBallotCustody(completion);
    return [
        '## Participant ballot custody',
        '',
        'Private ballot suffix and payload bounds, excluding the already retained participant root and its earlier records. The encoded suffix supplies no verification or signing authority by itself.',
        '',
        table(
            ['Property', 'Value'],
            [
                [
                    'Maximum ballot state bytes',
                    formatCount(participantBallotCustody.maximumStateBytes),
                ],
                [
                    'Maximum body records',
                    formatCount(participantBallotCustody.maximumBodyRecords),
                ],
                [
                    'Maximum encrypted body bytes',
                    formatCount(
                        participantBallotCustody.maximumEncryptedBodyBytes,
                    ),
                ],
                ...participantBallotCustody.phaseBytes.map((value) => [
                    'Phase ' + value.phase + ' state bytes',
                    formatCount(value.bytes),
                ]),
            ],
        ),
        '',
    ];
};

export const renderParticipantCloseCustody = (): string[] => {
    const completion = completionProfile();
    const participantCloseCustody = compileParticipantCloseCustody(completion);
    const largestCloseCustody = compileParticipantCloseCustody(
        largestSupportedProfile(),
    );
    const thresholdProfiles = compileSupportedThresholdCompletionProfiles();
    return [
        '## Participant close custody',
        '',
        'Private close suffix and record bounds, excluding the already retained participant root and its earlier records. The suffix retains the accepted close inputs in arrival order with one key per encrypted record, so restoration replays them into the same state through the owning state machine. Before an intent the suffix only collects, alongside every ballot phase. Held bodies bound the delivery events, since the state machine refuses an input that changes nothing, and only the organizer adds one event per other responder and retains its proposal exact body when its response completes. The per-roster table uses the completion option count, and the held bodies dominate the record bytes. The encoded suffix supplies no verification or signing authority by itself.',
        '',
        table(
            ['Property', 'Value'],
            [
                [
                    'Maximum close state bytes',
                    formatCount(participantCloseCustody.maximumStateBytes),
                ],
                [
                    'Maximum collecting state bytes',
                    formatCount(participantCloseCustody.collectingBytes),
                ],
                [
                    'Maximum close events',
                    formatCount(participantCloseCustody.maximumEvents),
                ],
                [
                    'Maximum close records',
                    formatCount(participantCloseCustody.maximumRecords),
                ],
                [
                    'Maximum encrypted close record bytes',
                    formatCount(
                        participantCloseCustody.maximumEncryptedRecordBytes,
                    ),
                ],
                [
                    'Maximum organizer encrypted close record bytes',
                    formatCount(
                        participantCloseCustody.maximumOrganizerEncryptedRecordBytes,
                    ),
                ],
                [
                    'Maximum organizer encrypted close record bytes at the largest profile',
                    formatCount(
                        largestCloseCustody.maximumOrganizerEncryptedRecordBytes,
                    ),
                ],
                ...participantCloseCustody.phaseBytes.map((value) => [
                    'Phase ' + value.phase + ' state bytes',
                    formatCount(value.bytes),
                ]),
            ],
        ),
        '',
        table(
            [
                'Participants',
                'Maximum close state bytes',
                'Maximum close events',
                'Maximum close records',
                'Maximum encrypted close record bytes',
                'Maximum organizer encrypted close record bytes',
            ],
            thresholdProfiles.map(({ participantCount }) => {
                const value = compileParticipantCloseCustody(
                    deriveSupportedProfile(
                        participantCount,
                        completionProfileCounts.optionCount,
                    ),
                );
                return [
                    formatCount(participantCount),
                    formatCount(value.maximumStateBytes),
                    formatCount(value.maximumEvents),
                    formatCount(value.maximumRecords),
                    formatCount(value.maximumEncryptedRecordBytes),
                    formatCount(value.maximumOrganizerEncryptedRecordBytes),
                ];
            }),
        ),
        '',
    ];
};

export const renderParticipantReleaseCustody = (): string[] => {
    const completion = completionProfile();
    const participantReleaseCustody =
        compileParticipantReleaseCustody(completion);
    return [
        '## Participant release custody',
        '',
        'Private release suffix and payload bounds for one original-key release under the retained certified target, excluding the earlier participant state. Repeated execution draws the same bytes from the retained seed. The encoded suffix supplies no verification or signing authority by itself.',
        '',
        table(
            ['Property', 'Value'],
            [
                [
                    'Authenticated proof role bytes',
                    formatCount(participantReleaseCustody.proofRoleBytes),
                ],
                [
                    'Maximum release state bytes',
                    formatCount(participantReleaseCustody.maximumStateBytes),
                ],
                [
                    'Maximum body bytes',
                    formatCount(participantReleaseCustody.maximumBodyBytes),
                ],
                [
                    'Maximum body records',
                    formatCount(participantReleaseCustody.maximumBodyRecords),
                ],
                [
                    'Maximum encrypted body bytes',
                    formatCount(
                        participantReleaseCustody.maximumEncryptedBodyBytes,
                    ),
                ],
                ...participantReleaseCustody.phaseBytes.map((value) => [
                    'Phase ' + value.phase + ' state bytes',
                    formatCount(value.bytes),
                ]),
            ],
        ),
        '',
    ];
};

export const renderFirstOracleCheckpointCensus = (): string[] => {
    const completion = completionProfile();
    const firstOracleCheckpoint =
        compileFirstOracleCheckpointCensus(completion);
    return [
        '## First-oracle checkpoint census',
        '',
        'The complete first-oracle checkpoint retains the actual witness, masks, leaf-salt seed, and partial row hashes. Lookup multiplicities, empty tree nodes, and the initial transcript are reconstructed. Each private record uses a separate data key. The browser root also retains encrypted generated public inputs and the source-link operands; other fixed common polynomials and verified recipient keys are reconstructed from predecessors. The proof-randomness minima split at this checkpoint: generation supplies the first-oracle masks and tree seed, while continuation supplies every response salt, starting with the salt preceding the lookup challenge. These minima exclude witness sampling and extra reads caused by rejected field candidates. Storage counts exclude database overhead and later proof phases, repeated checkpoints, and their security and resource unions.',
        '',
        table(
            ['Private field', 'Plaintext bytes', 'Encrypted records'],
            firstOracleCheckpoint.fields.map((field) => [
                field.name,
                formatCount(field.plaintextBytes),
                formatCount(field.recordCount),
            ]),
        ),
        '',
        table(
            ['Property', 'Value'],
            [
                [
                    'Minimum generation proof-randomness bytes',
                    formatCount(
                        firstOracleCheckpoint.minimumGenerationProofRandomBytes,
                    ),
                ],
                [
                    'Minimum continuation proof-randomness bytes',
                    formatCount(
                        firstOracleCheckpoint.minimumContinuationProofRandomBytes,
                    ),
                ],
                [
                    'Private encrypted records',
                    formatCount(firstOracleCheckpoint.recordCount),
                ],
                [
                    'Private checkpoint plaintext bytes',
                    formatCount(firstOracleCheckpoint.plaintextBytes),
                ],
                [
                    'Private checkpoint ciphertext bytes',
                    formatCount(firstOracleCheckpoint.ciphertextBytes),
                ],
                [
                    'Private record key bytes',
                    formatCount(firstOracleCheckpoint.dataKeyBytes),
                ],
                [
                    'Private record hash bytes',
                    formatCount(firstOracleCheckpoint.recordHashBytes),
                ],
                [
                    'Maximum private plaintext record bytes',
                    formatCount(
                        firstOracleCheckpoint.maximumPlaintextRecordBytes,
                    ),
                ],
                [
                    'Maximum private ciphertext record bytes',
                    formatCount(
                        firstOracleCheckpoint.maximumCiphertextRecordBytes,
                    ),
                ],
                [
                    'Checkpoint header bytes for the protocol role',
                    formatCount(firstOracleCheckpoint.headerBytes),
                ],
                [
                    'Checkpoint import bytes including routing context',
                    formatCount(firstOracleCheckpoint.importBytes),
                ],
                [
                    'Header digest input bytes including fixed domain',
                    formatCount(firstOracleCheckpoint.headerDigestInputBytes),
                ],
                [
                    'Header digest permutations per record',
                    formatCount(firstOracleCheckpoint.headerDigestPermutations),
                ],
                [
                    'Header digest permutations per complete seal or import pass',
                    formatCount(
                        firstOracleCheckpoint.headerDigestPermutationsPerPass,
                    ),
                ],
                [
                    'Maximum checkpoint header bytes',
                    formatCount(firstOracleCheckpoint.maximumHeaderBytes),
                ],
                [
                    'Encrypted public-input records',
                    formatCount(firstOracleCheckpoint.publicRecordCount),
                ],
                [
                    'Public-input plaintext bytes',
                    formatCount(firstOracleCheckpoint.publicPlaintextBytes),
                ],
                [
                    'Public-input ciphertext bytes',
                    formatCount(firstOracleCheckpoint.publicCiphertextBytes),
                ],
                [
                    'Maximum browser root plaintext bytes',
                    formatCount(
                        firstOracleCheckpoint.maximumRootPlaintextBytes,
                    ),
                ],
                [
                    'Maximum retained checkpoint payload bytes',
                    formatCount(
                        firstOracleCheckpoint.maximumRetainedPayloadBytes,
                    ),
                ],
            ],
        ),
        '',
    ];
};

export const renderSharedParticipantCustodyCensus = (): string[] => {
    const completion = completionProfile();
    const participantCustody = compileParticipantCustodyCensus(completion);
    const contributionProofStorage =
        compileContributionProofStorage(completion);
    return [
        '## Shared participant custody census',
        '',
        'The shared root retains original enrollment records, the selected signed proposal, contribution state, and signing-record keys and identities. The expanded statement header is regenerated rather than retained as another body record. The existing length-prefixed contribution header field instead retains the canonical contribution body header from completed generation onward, replacing the retired first-oracle progress header. Proof storage seals exactly the authenticated proof length in complete chunks and one final partial chunk when needed. A complete consumer pass authenticates every required record before commitment completion; the existing body-commitment preflight precedes publication. Maximum payload, record-key, tag and reference envelopes remain capacity bounds. The body header is retained in both representations, so storage savings exclude its length. The payload bound includes checkpoint/body overlap and signing records; browser database, key-store, and journal overhead remain measured quantities.',
        '',
        table(
            ['Property', 'Value'],
            [
                ['Participants', formatCount(participantCustody.participants)],
                [
                    'Owned polynomial records',
                    formatCount(participantCustody.publicRecords.length),
                ],
                [
                    'Private checkpoint records',
                    formatCount(participantCustody.checkpointLengths.length),
                ],
                [
                    'Contribution metadata prefix bytes',
                    formatCount(participantCustody.metadataPrefixBytes),
                ],
                [
                    'Maximum checkpoint metadata bytes',
                    formatCount(
                        participantCustody.maximumCheckpointMetadataBytes,
                    ),
                ],
                [
                    'Maximum completed metadata bytes',
                    formatCount(
                        participantCustody.maximumCompletedMetadataBytes,
                    ),
                ],
                [
                    'Retained completed body-header bytes',
                    formatCount(participantCustody.completedBodyHeaderBytes),
                ],
                [
                    'Maximum proof storage slots',
                    formatCount(contributionProofStorage.records.length),
                ],
                [
                    'Maximum proof plaintext capacity bytes',
                    formatCount(contributionProofStorage.plaintextBytes),
                ],
                [
                    'Maximum encrypted proof capacity bytes',
                    formatCount(contributionProofStorage.ciphertextBytes),
                ],
                [
                    'Maximum proof record-key bytes',
                    formatCount(contributionProofStorage.dataKeyBytes),
                ],
                [
                    'Maximum proof record-identity bytes',
                    formatCount(contributionProofStorage.recordIdentityBytes),
                ],
                [
                    'Maximum proof reference bytes in root',
                    formatCount(contributionProofStorage.recordReferenceBytes),
                ],
                [
                    'Maximum encrypted participant root bytes',
                    formatCount(participantCustody.maximumRootBytes),
                ],
                [
                    'Maximum release state bytes',
                    formatCount(participantCustody.maximumReleaseStateBytes),
                ],
                [
                    'Maximum close state bytes',
                    formatCount(participantCustody.maximumCloseStateBytes),
                ],
                [
                    'Maximum target-signing state bytes',
                    formatCount(
                        participantCustody.maximumTargetSigningStateBytes,
                    ),
                ],
                [
                    'Maximum participant root records',
                    formatCount(participantCustody.maximumRootRecords),
                ],
                [
                    'Retained setup reference bytes',
                    formatCount(participantCustody.setupReferenceBytes),
                ],
                [
                    'Maximum public body ciphertext bytes',
                    formatCount(
                        participantCustody.maximumPublicBodyCiphertextBytes,
                    ),
                ],
                [
                    'Maximum signing plaintext payload bytes',
                    formatCount(
                        participantCustody.maximumSigningPlaintextBytes,
                    ),
                ],
                [
                    'Maximum retained payload and overlap bytes',
                    formatCount(participantCustody.maximumRetainedPayloadBytes),
                ],
            ],
        ),
        '',
        'Preparation and later roots have distinct inventories. The preparation journal frames independent own-offer, selection and endorsement slots, and the own offer carries its own phase. Activation authenticates the complete predecessor before clearing all slots and retiring source material. Later roots therefore retain an empty preparation journal beside ballot, close, target and release state.',
        '',
        table(
            ['Authenticated journal property', 'Bytes'],
            [
                [
                    'Empty preparation journal',
                    formatCount(participantCustody.emptyPreparationBytes),
                ],
                [
                    'Maximum own-offer state',
                    formatCount(participantCustody.maximumMetadataBytes),
                ],
                [
                    'Maximum organizer selection slot',
                    formatCount(participantCustody.maximumSelectionSlotBytes),
                ],
                [
                    'Maximum endorsement slot',
                    formatCount(participantCustody.maximumEndorsementSlotBytes),
                ],
                [
                    'Maximum complete preparation journal',
                    formatCount(participantCustody.maximumPreparationBytes),
                ],
                [
                    'Maximum preparation root',
                    formatCount(participantCustody.maximumPreparationRootBytes),
                ],
                [
                    'Maximum prepared later root',
                    formatCount(participantCustody.maximumPreparedRootBytes),
                ],
            ],
        ),
        '',
        'Actual padding growth depends on an observed complete proof length `L`, not the header-only framing lower bound, which does not establish an achievable proof. With capacity `P`, chunk size `C`, `M=ceil(P/C)` and `m=ceil(L/C)`, the added proof payload is `P-L`, the added record count is `M-m`, and added encrypted proof bytes are `P-L+16*(M-m)`. The completed root adds the body header and `106*(M-m)` reference bytes; the root tag count does not change. Each actual full authentication/consumer pass reads that complete encrypted proof delta again, and an ordinary write pays it once. The [participant custody model](../tests/participant-custody-model.ts) takes the observed length and explicit pass count; it assumes no extra preflight passes and does not turn per-pass costs into lifetime populations. Checkpoint authentication and atomic retirement remain required, with their payload already included in the overlap bound. Public proof bytes remain the original `L`-byte prefix.',
        '',
    ];
};

export const renderParticipantVaultKeyWork = (): string[] => {
    const completion = completionProfile();
    return [
        '## Participant vault key work',
        '',
        'These per-key upper bounds follow the emitted fixed-nonce AES-GCM layouts. Initial intent and completion share one key with distinct nonces; every later root and child record uses a fresh key. Corpus counts exclude aborted writes, abandoned enrollment and recovery. They are not lifetime key limits. Later-root counts and every lifetime encryption/read population remain unmeasured; repeated reads add work even when they reuse existing block inputs. The root nonce in a single-use class is normalized because its value does not change these per-key counts.',
        '',
        table(
            [
                'Key class',
                'Maximum keys per completed corpus',
                'Encryption calls per key',
                'Maximum AES inputs for encryption',
                'Algorithmic encryption AES call bound',
                'Maximum GHASH degree',
            ],
            compileParticipantVaultKeyClasses(completion).map((value) => [
                value.name,
                value.maximumPerCompletedCorpus === null
                    ? 'Unmeasured'
                    : formatCount(value.maximumPerCompletedCorpus),
                formatCount(value.encryptionWork.invocations),
                formatCount(value.encryptionWork.distinctAesInputUpperBound),
                formatCount(value.encryptionWork.algorithmicAesCallUpperBound),
                formatCount(value.encryptionWork.maximumHashDegree),
            ]),
        ),
        '',
        'For a supplied complete per-key history, the [participant custody model](../tests/participant-custody-model.ts) separately counts encryption and verification invocations, repeated block computations and the union of block inputs. Its statistical numerators are conditional on the stated secret-key PRP replacement; the AES assumption, full populations and whole-protocol advantage are additional obligations.',
        '',
    ];
};

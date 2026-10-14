import {
    compileBrowserWordProverResources,
    compileContributionGenerationResources,
} from '#tests/browser-word-prover-resource-model.js';
import { compileContributionBodyCensus } from '#tests/contribution-body-model.js';
import { compileOrdinaryWorkflowResources } from '#tests/ordinary-workflow-resource-model.js';
import { compileSetupAggregateResources } from '#tests/setup-aggregate-resource-model.js';
import {
    compileSetupRandomnessCensus,
    setupGaussianParameters,
} from '#tests/setup-randomness-model.js';
import {
    completionProfile,
    largestSupportedProfile,
} from '#tests/supported-profile-model.js';
import { formatCount, table } from '#tools/ci/census/format.js';
import { readParticipantArtifactResources } from '#tools/ci/participant-artifact-resources.js';

export const renderBrowserWordProverResourceCensus = (): string[] => {
    const completion = completionProfile();
    const browserWordProver = compileBrowserWordProverResources(completion);
    return [
        '## Browser word-prover resource census',
        '',
        'The browser experiment streams public inputs, retains their prepared common-polynomial adjoints until the affine pass, and emits one proof record at a time. These conservative allocation allowances describe the experimental live-data schedule. They are not measurements of browser-private memory, authenticated checkpoints, a complete action, or supported-phone qualification.',
        '',
        table(
            ['Property', 'Value'],
            [
                [
                    'Full-degree common-polynomial adjoints',
                    formatCount(browserWordProver.fullDegreeCommonPolynomials),
                ],
                [
                    'Prepared adjoint bytes',
                    formatCount(browserWordProver.preparedAdjointBytes),
                ],
                [
                    'Enforced maximum bytes per opaque hasher',
                    formatCount(browserWordProver.maximumHasherBytes),
                ],
                [
                    'Metadata and allocator allowance bytes',
                    formatCount(
                        browserWordProver.metadataAndAllocatorAllowance,
                    ),
                ],
                ...browserWordProver.stages.map((stage) => [
                    `Allocation allowance: ${stage.stage}`,
                    formatCount(stage.bytes),
                ]),
            ],
        ),
        '',
    ];
};

export const renderContributionGenerationAndSamplingCensus = (): string[] => {
    const completion = completionProfile();
    const setupRandomness = compileSetupRandomnessCensus(completion);
    const contributionGeneration =
        compileContributionGenerationResources(completion);
    return [
        '## Contribution generation and sampling census',
        '',
        'The combined browser path keeps witness columns inside Rust, regenerates fixed common polynomials, and retains the remaining public statement and proof as bounded local blobs. Allocation allowances require measured closure. The sampling rows describe one completed roster whose original poll maximum equals its displayed size: every enrolled participant samples its recipient error and every source family, then the complete eligible pool reuses each original first error while sampling its remaining contribution errors. A different original maximum is an explicit model operand. The sampling bound charges finite-word quantization and the omitted Gaussian tails for that local corpus; it does not bound abandoned credentials or establish lattice or composed-protocol security.',
        '',
        table(
            ['Property', 'Value'],
            [
                [
                    'Gaussian density parameter numerator',
                    formatCount(setupGaussianParameters.sigmaNumerator),
                ],
                [
                    'Gaussian density parameter denominator',
                    formatCount(setupGaussianParameters.sigmaDenominator),
                ],
                [
                    'Gaussian sample bits',
                    formatCount(setupGaussianParameters.sampleBits),
                ],
                [
                    'Encoded nonterminal cumulative thresholds',
                    formatCount(setupRandomness.thresholdCount),
                ],
                [
                    'Cumulative table bytes',
                    formatCount(setupRandomness.encodedThresholdBytes),
                ],
                [
                    'Fresh error samples per contribution operation',
                    formatCount(setupRandomness.samplesPerContribution),
                ],
                [
                    'Original poll maximum for these sampling rows',
                    formatCount(
                        setupRandomness.originalPollMaximumParticipants,
                    ),
                ],
                [
                    'Source families per enrollment',
                    formatCount(setupRandomness.sourceFamilyCount),
                ],
                [
                    'Error samples per original source family',
                    formatCount(setupRandomness.samplesPerSourceFamily),
                ],
                [
                    'Recipient and source error samples per enrollment',
                    formatCount(setupRandomness.samplesPerEnrollment),
                ],
                [
                    'Error samples across preparation and registration',
                    formatCount(setupRandomness.samplesPerPreparation),
                ],
                [
                    'Gaussian uniform sample bytes per contribution operation',
                    formatCount(setupRandomness.contributionSampleBytes),
                ],
                [
                    'Preparation sampling-distance exponent',
                    formatCount(setupRandomness.preparationSamplingBits),
                ],
                [
                    'Witness-generation allocation allowance bytes',
                    formatCount(contributionGeneration.generationAllowance),
                ],
                [
                    'Combined allocation allowance bytes',
                    formatCount(contributionGeneration.combinedAllowance),
                ],
                [
                    'Retained verified-roster payload bytes',
                    formatCount(
                        contributionGeneration.retainedRosterPayloadBytes,
                    ),
                ],
                [
                    'Additional roster input-buffer bytes',
                    formatCount(
                        contributionGeneration.additionalInputBufferBytes,
                    ),
                ],
                [
                    'Public coefficient allocation allowance bytes',
                    formatCount(
                        contributionGeneration.publicCoefficientAllowance,
                    ),
                ],
                [
                    'Expanded public working bytes',
                    formatCount(
                        contributionGeneration.expandedPublicWorkingBytes,
                    ),
                ],
                [
                    'Regenerated common-polynomial bytes',
                    formatCount(contributionGeneration.regeneratedCommonBytes),
                ],
                [
                    'Reused verified recipient-key bytes',
                    formatCount(contributionGeneration.reusedRecipientBytes),
                ],
                [
                    'Retained public working bytes',
                    formatCount(contributionGeneration.publicWorkingBytes),
                ],
                [
                    'Maximum public emission batch bytes',
                    formatCount(
                        contributionGeneration.maximumPublicEmissionBatch,
                    ),
                ],
            ],
        ),
        '',
    ];
};

export const renderContributionBodyCensus = (): string[] => {
    const completion = completionProfile();
    const contributionBody = compileContributionBodyCensus(completion);
    return [
        '## Contribution body census',
        '',
        'The active profile frames one complete contribution as a fixed header, its owned public polynomials in the compiled statement order, and its complete proof. Fixed common inputs, the statement header, and previously verified recipient keys are reconstructed from predecessors. The body is a virtual concatenation of bounded records; these payload counts do not allocate another whole-body copy or include checkpoint, database or signature overhead.',
        '',
        table(
            ['Property', 'Value'],
            [
                [
                    'Participants',
                    formatCount(contributionBody.participantCount),
                ],
                [
                    'Owned public polynomials',
                    formatCount(contributionBody.polynomials.length),
                ],
                [
                    'Body header bytes',
                    formatCount(contributionBody.headerBytes),
                ],
                [
                    'Owned polynomial payload bytes',
                    formatCount(contributionBody.polynomialPayloadBytes),
                ],
                [
                    'Minimum proof framing bytes',
                    formatCount(contributionBody.minimumProofBytes),
                ],
                [
                    'Maximum proof bytes',
                    formatCount(contributionBody.maximumProofBytes),
                ],
                [
                    'Maximum complete body bytes',
                    formatCount(contributionBody.maximumBodyBytes),
                ],
                [
                    'Registered-coordinate opening salt bytes inside SCB2',
                    formatCount(contributionBody.sourceOpeningSaltBytes),
                ],
                [
                    'Ordinary body hash-prefix bytes',
                    formatCount(contributionBody.hashPrefixBytes),
                ],
                [
                    'Minimum ordinary body hash-input bytes',
                    formatCount(contributionBody.minimumHashInputBytes),
                ],
                [
                    'Maximum ordinary body hash-input bytes',
                    formatCount(contributionBody.maximumHashInputBytes),
                ],
                [
                    'Minimum input enclosing bit exponent',
                    formatCount(
                        contributionBody.minimumHashInputEnclosingBitExponent,
                    ),
                ],
                [
                    'Maximum input enclosing bit exponent',
                    formatCount(
                        contributionBody.maximumHashInputEnclosingBitExponent,
                    ),
                ],
                [
                    'Maximum eligible-offer body payload bytes',
                    formatCount(contributionBody.maximumEligibleOfferBodies),
                ],
            ],
        ),
        '',
    ];
};

export const renderSetupAggregateCacheCensus = (): string[] => {
    const completion = completionProfile();
    const setupAggregate = compileSetupAggregateResources(completion);
    return [
        '## Setup aggregate cache census',
        '',
        'The public aggregator replaces one coefficient-aligned chunk of the previous ordinal in each awaited atomic put/delete transaction. The resulting mixed cache is disposable scratch until complete offer verification and all aggregate digests succeed; failure clears it and drops the aggregator while preserving verified offer holders and authenticated private authority. Counts below bound logical payload and successful cache traffic; physical database journals, garbage collection, allocation overhead, failed candidates and participant private state require separate evidence.',
        '',
        table(
            ['Property', 'Value'],
            [
                [
                    'Canonical aggregate bytes',
                    formatCount(setupAggregate.aggregateBytes),
                ],
                [
                    'Aggregate coefficients',
                    formatCount(setupAggregate.coefficients),
                ],
                [
                    'Chunks per cache generation',
                    formatCount(setupAggregate.cacheChunks),
                ],
                [
                    'Maximum cache read bytes',
                    formatCount(setupAggregate.maximumReadBytes),
                ],
                [
                    'Largest complete polynomial bytes',
                    formatCount(setupAggregate.maximumPolynomialBytes),
                ],
                [
                    'Logical cache payload including one replacement chunk',
                    formatCount(setupAggregate.maximumLogicalCachePayloadBytes),
                ],
                [
                    'Contribution polynomial read bytes',
                    formatCount(setupAggregate.contributionReadBytes),
                ],
                [
                    'Previous-generation cache read bytes',
                    formatCount(setupAggregate.previousCacheReadBytes),
                ],
                [
                    'Provisional cache write bytes',
                    formatCount(setupAggregate.provisionalCacheWriteBytes),
                ],
                [
                    'Complete final readback bytes',
                    formatCount(setupAggregate.completeReadbackBytes),
                ],
            ],
        ),
        '',
    ];
};

export const renderCompleteOrdinaryWorkflowResourceScreen = (): string[] => {
    const completion = completionProfile();
    const resourceArtifact = readParticipantArtifactResources();
    const workflowResources = [completion, largestSupportedProfile()].map(
        (profile) =>
            compileOrdinaryWorkflowResources(
                profile,
                readParticipantArtifactResources(),
            ),
    );
    return [
        '## Complete ordinary workflow resource screen',
        '',
        'The [workflow model](../tests/ordinary-workflow-resource-model.ts) follows one successful ordinary traversal with all roster members casting, responding, evaluating, voting, releasing and reading the result. Its ordinary schedule generates only the selected contributors; the separate eligible-corpus row allows every eligible author to publish. Body sizes are canonical maxima, not predictions of sampled proof sizes. The [candidate publication model](../tests/candidate-publication-model.ts) enumerates each complete manifest, immutable uploaded chunk, discovery entry, logical-key record, receipt and named readback. It includes repeated registration, poll, certificate and close-intent publications. Responders and the organizer forward immutable body references only after comparing every referenced byte with their authenticated custody; unavailable original chunks require uploading those same retained bytes. The stored-corpus figures count protocol payload and routing records, with filesystem allocation and journal costs separate. Publication readback totals are additional to ordinary public-input reads. Invalid inputs, retries and arbitrary extra visits have no finite lifetime population here.',
        '',
        'The artifact operands below come from the existing shared SDK build. Census generation verifies every recorded source digest and the packaged runtime identity, refuses a missing or stale build, and never triggers a build. Regenerate and check this section after the shared SDK build. These byte lengths identify delivered artifacts, not a phone measurement. The SDK embeds the worker source and creates worker/helper Blob URLs, so network bootstrap is one SDK bundle per page load plus one module per actual primary-worker invocation; the embedded worker is not charged twice. The ordinary target-signing call uses one worker, and the subsequent release/result calls restore its intact target. A cache-miss release/result call can automatically start a second worker and must charge both module fetches. Host-page bytes, transport headers and application delivery remain separate operands.',
        '',
        table(
            ['Built runtime operand', 'Value'],
            [
                [
                    'Runtime identity',
                    `\`${resourceArtifact.identity.runtime}\``,
                ],
                ['SDK entry digest', `\`${resourceArtifact.sdkDigest}\``],
                [
                    'SDK bundle bytes per page load',
                    formatCount(resourceArtifact.sdkBytes),
                ],
                [
                    'Module bytes per operation invocation',
                    formatCount(resourceArtifact.moduleBytes),
                ],
                [
                    'Embedded worker source bytes',
                    formatCount(resourceArtifact.workerBytes),
                ],
            ],
        ),
        '',
        table(
            ['Property', ...workflowResources.map((value) => value.profile)],
            [
                [
                    'Ordinary selected offer count',
                    (value: (typeof workflowResources)[number]) =>
                        value.rows[0].offers,
                ],
                [
                    'All-eligible offer count',
                    (value: (typeof workflowResources)[number]) =>
                        value.rows[1].offers,
                ],
                [
                    'Ordinary complete public corpus bytes',
                    (value: (typeof workflowResources)[number]) =>
                        value.rows[0].publicCorpusBytes,
                ],
                [
                    'All-eligible complete public corpus bytes',
                    (value: (typeof workflowResources)[number]) =>
                        value.rows[1].publicCorpusBytes,
                ],
                [
                    'Ordinary total upload bytes',
                    (value: (typeof workflowResources)[number]) =>
                        value.rows[0].totalUploadBytes,
                ],
                [
                    'All-eligible total upload bytes',
                    (value: (typeof workflowResources)[number]) =>
                        value.rows[1].totalUploadBytes,
                ],
                [
                    'Organizer upload bytes',
                    (value: (typeof workflowResources)[number]) =>
                        value.organizerUploadBytes,
                ],
                [
                    'Organizer closure copies',
                    (value: (typeof workflowResources)[number]) =>
                        value.organizerClosureCopyBytes,
                ],
                [
                    'Responders’ listed-envelope copies',
                    (value: (typeof workflowResources)[number]) =>
                        value.responderListedCopyBytes,
                ],
                [
                    'Maximum body reupload when original references are unavailable',
                    (value: (typeof workflowResources)[number]) =>
                        value.maximumMissingReferenceUploadBytes,
                ],
                [
                    'Bodies forwarded by byte-checked references',
                    (value: (typeof workflowResources)[number]) =>
                        value.ordinaryReferencedBodyBytes,
                ],
                [
                    'Publication readbacks, reference checks and receipts',
                    (value: (typeof workflowResources)[number]) =>
                        value.publicationReceivedBytes,
                ],
                [
                    'Publication requests including reference checks',
                    (value: (typeof workflowResources)[number]) =>
                        value.candidatePublicationRequests,
                ],
                [
                    'Uploaded candidate manifest bytes',
                    (value: (typeof workflowResources)[number]) =>
                        value.candidateManifestBytes,
                ],
                [
                    'Largest emitted candidate manifest',
                    (value: (typeof workflowResources)[number]) =>
                        value.maximumManifestBytes,
                ],
                [
                    'Largest emitted candidate file count',
                    (value: (typeof workflowResources)[number]) =>
                        value.maximumManifestFiles,
                ],
                [
                    'Outcome verifier routing metadata',
                    (value: (typeof workflowResources)[number]) =>
                        value.publicReaderRoutingBytes,
                ],
                [
                    'Fresh outcome verifier protocol bytes',
                    (value: (typeof workflowResources)[number]) =>
                        value.publicReaderProtocolBytes,
                ],
                [
                    'Fresh outcome verifier plus one SDK/module delivery',
                    (value: (typeof workflowResources)[number]) =>
                        value.publicReaderColdDeliveryBytes,
                ],
                [
                    'Ordinary operation-worker invocations',
                    (value: (typeof workflowResources)[number]) =>
                        value.rows[0].workerInvocations,
                ],
                [
                    'All-eligible operation-worker invocations',
                    (value: (typeof workflowResources)[number]) =>
                        value.rows[1].workerInvocations,
                ],
                [
                    'Ordinary module-download bytes across participants',
                    (value: (typeof workflowResources)[number]) =>
                        value.rows[0].moduleDownloadBytes,
                ],
            ].map(([label, select]) => [
                label as string,
                ...workflowResources.map((value) =>
                    formatCount(
                        (
                            select as (
                                value: (typeof workflowResources)[number],
                            ) => bigint
                        )(value),
                    ),
                ),
            ]),
        ),
        '',
        'The outcome verifier has no participant custody and streams every usable submission for barrier authentication, classification and evaluation import before checking the target votes and release shares. Participants with intact close custody read those bodies locally. Roster restoration refetches complete registered headers and recipient keys, recomputing their canonical body identities against its retained verification. Metadata allowances are conservative: held close responses can avoid target reads, and an existing setup certificate avoids assembly reads. These are protocol-read upper bounds, not exact ordinary network traces. The action rows exclude bootstrap; add the actual module for each primary-worker invocation and the SDK for each page load. Cumulative download rows are distinct from the per-action planning target.',
        '',
        table(
            [
                'Clean protocol read upper bound',
                ...workflowResources.map((value) => value.profile),
            ],
            [
                [
                    'One roster restoration',
                    (value: (typeof workflowResources)[number]) =>
                        value.rosterRestoreBytes,
                ],
                [
                    'Preparation endorsement and activation',
                    (value: (typeof workflowResources)[number]) =>
                        value.preparationReaderBytes,
                ],
                [
                    'Organizer selection, endorsement and activation',
                    (value: (typeof workflowResources)[number]) =>
                        value.preparationOrganizerBytes,
                ],
                [
                    'Other member’s two close invocations',
                    (value: (typeof workflowResources)[number]) =>
                        value.nonorganizerCloseBytes,
                ],
                [
                    'Organizer’s two close invocations',
                    (value: (typeof workflowResources)[number]) =>
                        value.organizerCloseBytes,
                ],
                [
                    'Target action',
                    (value: (typeof workflowResources)[number]) =>
                        value.targetReadBytes,
                ],
                [
                    'Release action with retained target',
                    (value: (typeof workflowResources)[number]) =>
                        value.releaseReadBytes,
                ],
                [
                    'Result action with retained target',
                    (value: (typeof workflowResources)[number]) =>
                        value.resultReadBytes,
                ],
                [
                    'Cumulative member without an offer',
                    (value: (typeof workflowResources)[number]) =>
                        value.noncontributorProtocolReads,
                ],
                [
                    'Cumulative member with one offer',
                    (value: (typeof workflowResources)[number]) =>
                        value.contributorProtocolReads,
                ],
                [
                    'Cumulative organizer',
                    (value: (typeof workflowResources)[number]) =>
                        value.organizerProtocolReads,
                ],
            ].map(([label, select]) => [
                label as string,
                ...workflowResources.map((value) =>
                    formatCount(
                        (
                            select as (
                                value: (typeof workflowResources)[number],
                            ) => bigint
                        )(value),
                    ),
                ),
            ]),
        ),
        '',
    ];
};

export const renderScalarEvaluationStorageScreen = (): string[] => {
    const completion = completionProfile();
    const workflowResources = [completion, largestSupportedProfile()].map(
        (profile) =>
            compileOrdinaryWorkflowResources(
                profile,
                readParticipantArtifactResources(),
            ),
    );
    return [
        '## Scalar evaluation storage screen',
        '',
        'The [independent storage model](../tests/evaluation-storage-model.ts) emits the existing algebraic ranking DAG in the Rust program’s DFS order and interprets the scalar capacity and eviction policy without ciphertexts or proofs. It preserves the pinned completion-program identity. The farthest next use is evicted first, with greatest index breaking ties; a reloaded value keeps its stored copy until final use. Old host key records coexist with newly written spills before awaited cache deletion, and replacement ordinal writes follow that deletion. These are successful logical store payloads; physical database journals, garbage collection, Blob allocation and process memory are separate evidence.',
        '',
        table(
            [
                'Scalar schedule operand',
                ...workflowResources.map((value) => value.profile),
            ],
            [
                [
                    'Instructions',
                    (value: (typeof workflowResources)[number]) =>
                        BigInt(value.evaluation.program.instructions.length),
                ],
                [
                    'One stored ciphertext bytes',
                    (value: (typeof workflowResources)[number]) =>
                        value.evaluation.capacity.storedValueBytes,
                ],
                [
                    'Multiplication-key record bytes',
                    (value: (typeof workflowResources)[number]) =>
                        value.evaluation.capacity.multiplicationKeyBytes,
                ],
                [
                    'One scalar job allowance bytes',
                    (value: (typeof workflowResources)[number]) =>
                        value.evaluation.capacity.jobBytes,
                ],
                [
                    'First spill writes',
                    (value: (typeof workflowResources)[number]) =>
                        BigInt(value.evaluation.spillCount),
                ],
                [
                    'Reloads',
                    (value: (typeof workflowResources)[number]) =>
                        BigInt(value.evaluation.reloadCount),
                ],
                [
                    'Resident-only drops of stored values',
                    (value: (typeof workflowResources)[number]) =>
                        BigInt(value.evaluation.dropCount),
                ],
                [
                    'Peak live spilled values',
                    (value: (typeof workflowResources)[number]) =>
                        BigInt(value.evaluation.peakStored),
                ],
                [
                    'Peak evaluation-store payload bytes',
                    (value: (typeof workflowResources)[number]) =>
                        value.evaluation.peakBytes,
                ],
                [
                    'Scratch planning variance ceiling',
                    (value: (typeof workflowResources)[number]) =>
                        value.evaluation.scratchVarianceCeilingBytes,
                ],
                [
                    'All key-bank writes',
                    (value: (typeof workflowResources)[number]) =>
                        value.evaluation.keyBankWriteBytes,
                ],
                [
                    'Spill writes and matching readback, each',
                    (value: (typeof workflowResources)[number]) =>
                        value.evaluation.spillWriteBytes,
                ],
                [
                    'Reload read bytes',
                    (value: (typeof workflowResources)[number]) =>
                        value.evaluation.reloadBytes,
                ],
                [
                    'Preparation retained and aggregate payload subtotal',
                    (value: (typeof workflowResources)[number]) =>
                        value.prepRetainedAndAggregatePayloadBytes,
                ],
                [
                    'Closed custody and aggregate payload subtotal',
                    (value: (typeof workflowResources)[number]) =>
                        value.closedCustodyAndAggregatePayloadBytes,
                ],
                [
                    'Evaluation custody, aggregate and store payload subtotal',
                    (value: (typeof workflowResources)[number]) =>
                        value.evaluationCustodyAndStorePayloadBytes,
                ],
                [
                    'Completed release payload subtotal',
                    (value: (typeof workflowResources)[number]) =>
                        value.releaseEndPayloadBytes,
                ],
                [
                    'Maximum retained target Vec / immutable Blob bytes',
                    (value: (typeof workflowResources)[number]) =>
                        value.retainedTarget.maximumRetainedBytes,
                ],
                [
                    'Maximum retained-target copied slice bytes',
                    (value: (typeof workflowResources)[number]) =>
                        value.retainedTarget.maximumSliceBytes,
                ],
                [
                    'Local publication data-kind payload reads across participants',
                    (value: (typeof workflowResources)[number]) =>
                        value.publicationRecordPayloadReadBytes,
                ],
                [
                    'Maximum registration-publication record bytes',
                    (value: (typeof workflowResources)[number]) =>
                        value.maximumPublicationRecordBytes,
                ],
            ].map(([label, select]) => [
                label as string,
                ...workflowResources.map((value) =>
                    formatCount(
                        (
                            select as (
                                value: (typeof workflowResources)[number],
                            ) => bigint
                        )(value),
                    ),
                ),
            ]),
        ),
        '',
        'The retained-target repair bounds each copied JavaScript slice while preserving the full Rust output and single immutable stored Blob. Public data-kind publication now uses a complete preflight followed by guarded record-sized delivery; the local payload-read row charges those two passes, with root/head/count authority checks additional and no change to upload bytes. The custody subtotals still need residual record/head metadata, restart overlap and physical storage accounting before they establish a complete origin-storage bound. The largest profile remains outside the scratch planning variance ceiling and its organizer’s preparation polynomial-read floor remains outside the transfer variance ceiling; no largest-profile resource closure follows from the smaller ordinary corpus or bounded copy repair.',
        '',
    ];
};

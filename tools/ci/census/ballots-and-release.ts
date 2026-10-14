import { auxiliaryInputEncryptionParameters } from '#tests/auxiliary-input-encryption-parameters.js';
import { compileBallotBodyCensus } from '#tests/ballot-body-model.js';
import { compileBallotEncryptionRelationCensus } from '#tests/ballot-encryption-relation-model.js';
import {
    compileBallotWordProofLayout,
    compileLinkedReleaseWordProofLayout,
} from '#tests/full-word-proof-layout-model.js';
import { compileLinkedReleaseRelationCensus } from '#tests/linked-release-relation-model.js';
import { compileReleaseShareLiftingCensus } from '#tests/release-share-lifting-model.js';
import { compileReleaseVerificationWorkload } from '#tests/release-verification-work-model.js';
import { completionProfile } from '#tests/supported-profile-model.js';
import { compileWideShareLiftingCensus } from '#tests/wide-share-lifting-model.js';
import { formatCount, table } from '#tools/ci/census/format.js';

export const renderWideSharingAndReleaseLiftingCensus = (): string[] => {
    const completion = completionProfile();
    const wideShareLifting = compileWideShareLiftingCensus(
        completion.shareLifting,
    );
    const releaseShareLifting = compileReleaseShareLiftingCensus(
        completion.releaseLifting,
    );
    return [
        '## Wide sharing and release lifting census',
        '',
        'Candidate bounds for byte-aligned integer sharing and the dense release relation. The finite experiments independently construct the integer products, decrypt encrypted evaluations, and reproduce the out-of-range modular aliases. They do not implement the complete public proof or admit a distribution.',
        '',
        table(
            ['Property', 'Value'],
            [
                ['Share-encryption scale', formatCount(wideShareLifting.scale)],
                [
                    'Share-encryption modulus',
                    formatCount(wideShareLifting.modulus),
                ],
                [
                    'Nonconstant sharing coefficient radius',
                    formatCount(wideShareLifting.sharingRadius),
                ],
                [
                    'Nonconstant sharing coefficient bits',
                    formatCount(wideShareLifting.sharingCoefficientBits),
                ],
                [
                    'Share-encryption secret support weight',
                    formatCount(wideShareLifting.encryptionSupportWeight),
                ],
                [
                    'Shared FHE secret support weight',
                    formatCount(wideShareLifting.sharedSecretSupportWeight),
                ],
                [
                    'Joint sharing-translation numerator',
                    formatCount(wideShareLifting.privacyNumerator),
                ],
                [
                    'Aggregate sharing coefficient bound',
                    formatCount(wideShareLifting.aggregateSharingMaximum),
                ],
                ['Sharing limb radix', formatCount(wideShareLifting.radix)],
                [
                    'Sharing quotient magnitude bound',
                    formatCount(wideShareLifting.quotientBound),
                ],
                [
                    'Sharing carry magnitude bound',
                    formatCount(wideShareLifting.carryBound),
                ],
                [
                    'Complete sharing limb residual bound',
                    formatCount(wideShareLifting.residualBound),
                ],
                [
                    'Sharing equations checked',
                    formatCount(wideShareLifting.checkedEquations),
                ],
                [
                    'Carry needed by the false sharing equation',
                    formatCount(wideShareLifting.aliasCarry),
                ],
                [
                    'Dense release limb radix',
                    formatCount(releaseShareLifting.radix),
                ],
                [
                    'Dense release carry magnitude bound',
                    formatCount(releaseShareLifting.carryBound),
                ],
                [
                    'Complete dense release limb residual bound',
                    formatCount(releaseShareLifting.residualBound),
                ],
                [
                    'Dense release equations checked',
                    formatCount(releaseShareLifting.checkedEquations),
                ],
                [
                    'Carry needed by the false release equation',
                    formatCount(releaseShareLifting.aliasCarry),
                ],
            ],
        ),
        '',
    ];
};

export const renderLinkedBallotEncryptionCensus = (): string[] => {
    const completion = completionProfile();
    const ballotRelation = compileBallotEncryptionRelationCensus(completion);
    const ballotWordProof = compileBallotWordProofLayout(completion);
    return [
        '## Linked ballot encryption census',
        '',
        'The model links a complete bounded score vector to the exact FHE comparison-window packing, literal FHE score tail, and auxiliary score encryption. Every integer quotient, carry, and centered plaintext endpoint is explicit. The auxiliary scheme is for simulator input recovery; it has no participant decryption action.',
        '',
        table(
            ['Property', 'Value'],
            [
                [
                    'Auxiliary ring degree',
                    formatCount(auxiliaryInputEncryptionParameters.degree),
                ],
                [
                    'Auxiliary ciphertext modulus',
                    formatCount(auxiliaryInputEncryptionParameters.modulus),
                ],
                [
                    'Auxiliary plaintext modulus',
                    formatCount(
                        auxiliaryInputEncryptionParameters.plaintextModulus,
                    ),
                ],
                [
                    'Auxiliary plaintext scale',
                    formatCount(auxiliaryInputEncryptionParameters.scale),
                ],
                [
                    'Auxiliary ephemeral and proof-game secret support',
                    formatCount(auxiliaryInputEncryptionParameters.support),
                ],
                [
                    'Auxiliary good-key proof-game noise bound',
                    formatCount(ballotRelation.auxiliaryGoodKeyNoiseBound),
                ],
                ['FHE integer limbs', formatCount(ballotRelation.limbs)],
                [
                    'Honest FHE encryption quotient bound',
                    formatCount(ballotRelation.trueQuotientBound),
                ],
                [
                    'Honest FHE encryption carry bound',
                    formatCount(ballotRelation.trueCarryBound),
                ],
                [
                    'Accepted FHE limb residual bound',
                    formatCount(ballotRelation.residualBound),
                ],
                [
                    'Honest packing quotient bound',
                    formatCount(ballotRelation.packingQuotientBound),
                ],
                [
                    'Accepted packing residual bound',
                    formatCount(ballotRelation.packingResidualBound),
                ],
                [
                    'Accepted auxiliary residual bound',
                    formatCount(ballotRelation.auxiliaryResidualBound),
                ],
                ['Word columns', formatCount(ballotRelation.wordColumns)],
                ['Boolean columns', formatCount(ballotRelation.booleanColumns)],
                [
                    'Additional quadratic constraints',
                    formatCount(ballotRelation.additionalQuadraticConstraints),
                ],
                [
                    'Maximum simultaneously retained product input columns',
                    formatCount(ballotRelation.maximumLiveProductColumns),
                ],
                [
                    'Two-coset product input cache payload bytes',
                    formatCount(ballotRelation.zeroProductCacheBytes),
                ],
                [
                    'Proof header bytes',
                    formatCount(ballotWordProof.headerBytes),
                ],
                [
                    'First oracle row bytes',
                    formatCount(ballotWordProof.firstWidth),
                ],
                [
                    'Second oracle row bytes',
                    formatCount(ballotWordProof.secondWidth),
                ],
                [
                    'Maximum incremental proof bytes',
                    formatCount(ballotWordProof.maximumMultiproofBytes),
                ],
                [
                    'Maximum cached node digest bytes',
                    formatCount(ballotWordProof.maximumCachedNodeDigestBytes),
                ],
                [
                    'Retained leaf-salt seed bytes',
                    formatCount(ballotWordProof.saltSeedBytes),
                ],
                [
                    'Prover mask bytes',
                    formatCount(ballotWordProof.proverMaskBytes),
                ],
                [
                    'Minimum requested proof randomness bytes before field-sampling rejection',
                    formatCount(ballotWordProof.minimumRequestedRandomBytes),
                ],
                [
                    'Resident public operator payload bytes',
                    formatCount(ballotWordProof.residentPublicOperatorBytes),
                ],
                [
                    'Additional narrow memberships',
                    formatCount(ballotRelation.narrowMemberships),
                ],
                [
                    'Single-entry inverse columns',
                    formatCount(ballotRelation.lookupEntries),
                ],
                [
                    'Full-profile affine rows',
                    formatCount(ballotRelation.affineRows),
                ],
            ],
        ),
        '',
    ];
};

export const renderBallotBodyCensus = (): string[] => {
    const completion = completionProfile();
    const ballotBody = compileBallotBodyCensus(completion);
    return [
        '## Ballot body census',
        '',
        'The framed body carries the bound context, both ciphertext pairs, and the exact proof. The verifier obtains only the FHE aggregate public key from certified setup and derives the FHE common coordinate and both fixed auxiliary coordinates locally. The complete expanded relation still has eight polynomials. Framing alone supplies no signature, publication, or ballot authority.',
        '',
        table(
            ['Property', 'Value'],
            [
                ['Context bytes', formatCount(ballotBody.contextBytes)],
                [
                    'Protocol proof role bytes',
                    formatCount(ballotBody.proofRoleBytes),
                ],
                ['Body header bytes', formatCount(ballotBody.headerBytes)],
                [
                    'Ciphertext payload bytes',
                    formatCount(ballotBody.ciphertextBytes),
                ],
                [
                    'Reconstructed public input bytes',
                    formatCount(ballotBody.reconstructedInputBytes),
                ],
                [
                    'Certified setup key input bytes',
                    formatCount(ballotBody.setupKeyInputBytes),
                ],
                [
                    'Locally derived common and fixed-pair input bytes',
                    formatCount(ballotBody.locallyDerivedInputBytes),
                ],
                [
                    'Minimum proof bytes',
                    formatCount(ballotBody.minimumProofBytes),
                ],
                [
                    'Maximum proof bytes',
                    formatCount(ballotBody.maximumProofBytes),
                ],
                ['Signature bytes', formatCount(ballotBody.signatureBytes)],
                [
                    'Envelope header bytes',
                    formatCount(ballotBody.envelopeBytes),
                ],
                [
                    'Maximum body bytes',
                    formatCount(ballotBody.maximumBodyBytes),
                ],
                [
                    'Maximum signed body bytes',
                    formatCount(ballotBody.maximumSignedBodyBytes),
                ],
                [
                    'Body identity hash prefix bytes',
                    formatCount(ballotBody.hashPrefixBytes),
                ],
                [
                    'Maximum body identity hash input bytes',
                    formatCount(ballotBody.maximumHashInputBytes),
                ],
            ],
        ),
        '',
    ];
};

export const renderReleaseVerificationAttempts = (): string[] => {
    const releaseVerification = compileReleaseVerificationWorkload({
        replayedCandidates: 1n,
        changedEnvelopes: 0n,
        changedProofBodies: 0n,
    });
    return [
        '## Release verification attempts',
        '',
        'A valid relation body paired with a correctly signed envelope claiming the wrong body identity is rejected only after complete proof verification. The public context survives that rejection. These counts apply per complete attempt with that context already verified; multiply by the number of attempts. Exact replay, changed envelopes with a fixed proof, and changed proof bodies remain separate populations. Executed calls do not establish distinct oracle points, a simulator lower bound, a lifetime limit or a full reduction cost. The calls of every attempt are oracle calls of the experiment, so the comparisons assign the entire query cap to this core alone, before subtracting any other charged work. Signature work, common-polynomial expansion and any additional predecessor reload remain separately chargeable.',
        '',
        table(
            ['Property', 'Value'],
            [
                [
                    'Mandatory proof-core calls excluding Merkle work',
                    formatCount(
                        releaseVerification.perAttempt.minimumProofCoreQueries,
                    ),
                ],
                [
                    'Completed release-body digest passes outside the core',
                    formatCount(
                        releaseVerification.perAttempt
                            .completedBodyDigestPasses,
                    ),
                ],
                [
                    'Known calls excluding Merkle, signature and common-polynomial work',
                    formatCount(
                        releaseVerification.perAttempt.minimumKnownHashCalls,
                    ),
                ],
                [
                    'Full attempts within the query cap using the core upper bound',
                    formatCount(
                        releaseVerification.maximumAttemptsCoveredByCoreUpperBound,
                    ),
                ],
                [
                    'First attempt count exceeding the query cap from mandatory core calls alone',
                    formatCount(
                        releaseVerification.firstAttemptCountExceedingCoreLowerBound,
                    ),
                ],
            ],
        ),
        '',
    ];
};

export const renderLinkedReleaseRelationCensus = (): string[] => {
    const completion = completionProfile();
    const linkedRelease = compileLinkedReleaseRelationCensus(completion);
    const linkedReleaseProof = compileLinkedReleaseWordProofLayout(completion);
    return [
        '## Linked release relation census',
        '',
        'The recipient-key, encrypted aggregate-decryption, and dense partial-release equations use the same hidden share and original recipient secret. These are exact integer-lifting and layout values; the emitted proof and target capability remain separate.',
        '',
        table(
            ['Property', 'Value'],
            [
                [
                    'Hidden aggregate-share bits',
                    formatCount(linkedRelease.shareBits),
                ],
                [
                    'Aggregate decoding-error bits',
                    formatCount(linkedRelease.decodingErrorBits),
                ],
                [
                    'Aggregate decoding-quotient bits',
                    formatCount(linkedRelease.decodingQuotientBits),
                ],
                [
                    'Aggregate decoding-carry bits',
                    formatCount(linkedRelease.decodingCarryBits),
                ],
                [
                    'Honest decoding quotient bound',
                    formatCount(linkedRelease.trueDecodingQuotientBound),
                ],
                [
                    'Honest decoding carry bound',
                    formatCount(linkedRelease.trueDecodingCarryBound),
                ],
                [
                    'Accepted decoding residual bound',
                    formatCount(linkedRelease.decodingResidualBound),
                ],
                ['Word columns', formatCount(linkedRelease.wordColumns)],
                [
                    'Additional narrow memberships',
                    formatCount(linkedRelease.narrowMemberships),
                ],
                ['Boolean columns', formatCount(linkedRelease.booleanColumns)],
                [
                    'Single-entry inverse columns',
                    formatCount(linkedRelease.lookupEntries),
                ],
                [
                    'Full-profile affine rows',
                    formatCount(linkedRelease.affineRows),
                ],
                [
                    'First release-oracle row bytes',
                    formatCount(linkedReleaseProof.firstWidth),
                ],
                [
                    'Second release-oracle row bytes',
                    formatCount(linkedReleaseProof.secondWidth),
                ],
                [
                    'Maximum canonical release-proof bytes',
                    formatCount(linkedReleaseProof.maximumMultiproofBytes),
                ],
                [
                    'Resident release affine-operator bytes',
                    formatCount(linkedReleaseProof.residentPublicOperatorBytes),
                ],
            ],
        ),
        '',
    ];
};

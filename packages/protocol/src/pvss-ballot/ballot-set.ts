import { canonicalJson, deriveProtocolHash } from '@sealed-lattice/crypto';
import type {
    BallotPackageCandidate,
    CanonicalBallotSet,
    CanonicalBallotSetInput,
    CountedBallotPackage,
    InclusionProof,
    ProtocolHash,
    RefusalRecord,
    RejectedBallotCandidate,
    SignedBoardHead,
    SignedBoardOrder,
} from '@sealed-lattice/types';

import {
    verifyBoardConsistency,
    verifyInclusionProof,
} from '../board/index.js';
import {
    buildBoardHeadMap,
    compareCanonicalStrings,
    createRefusal,
    isNonNegativeInteger,
    uniqueStrings,
} from '../common/verification-helpers.js';

import { verifyBallotPackageShell } from './ballot-package.js';
import {
    compareSignedBoardOrder,
    isBeforeSignedBoardOrder,
    validatePollAndThreshold,
    validateRosterEntries,
} from './common.js';

const deriveBallotSetHash = (input: {
    readonly base: CanonicalBallotSetInput;
    readonly countedBallots: readonly CountedBallotPackage[];
    readonly rejectedCandidates: readonly RejectedBallotCandidate[];
}): ProtocolHash =>
    deriveProtocolHash('BallotSetHash', {
        ceremonyId: input.base.ceremonyId,
        closeRecordHash: input.base.closeRecordHash,
        countedBallotPackageHashes: input.countedBallots.map(
            (candidate) => candidate.ballotPackage.ballotPackageHash,
        ),
        duplicateBallotPolicyHash: input.base.duplicateBallotPolicyHash,
        electionManifestHash: input.base.electionManifestHash,
        pollSpecHash: input.base.pollSpecHash,
        includeRejectedCandidateSummariesInHash:
            input.base.includeRejectedCandidateSummariesInHash === true,
        purpose: 'canonical-ballot-set-v1',
        rejectedCandidates:
            input.base.includeRejectedCandidateSummariesInHash === true
                ? input.rejectedCandidates.map((candidate) => ({
                      ballotPackageHash: candidate.ballotPackageHash,
                      refusalCodes: candidate.refusalCodes,
                      signedBoardOrder: candidate.signedBoardOrder ?? null,
                      voterIdentity: candidate.voterIdentity ?? null,
                  }))
                : [],
        rosterHash: input.base.rosterHash,
        thresholdProfileHash: input.base.thresholdProfileHash,
        votingClosedBoardHeadHash: input.base.votingClosedBoardHeadHash,
    });

export const deriveBallotSetHashFromCanonicalSet = (
    ballotSet: Pick<
        CanonicalBallotSet,
        | 'ceremonyId'
        | 'closeRecordHash'
        | 'countedBallots'
        | 'duplicateBallotPolicyHash'
        | 'electionManifestHash'
        | 'includeRejectedCandidateSummariesInHash'
        | 'pollSpecHash'
        | 'rejectedCandidates'
        | 'rosterHash'
        | 'thresholdProfileHash'
        | 'votingClosedBoardHeadHash'
    >,
): ProtocolHash =>
    deriveProtocolHash('BallotSetHash', {
        ceremonyId: ballotSet.ceremonyId,
        closeRecordHash: ballotSet.closeRecordHash,
        countedBallotPackageHashes: ballotSet.countedBallots.map(
            (candidate) => candidate.ballotPackage.ballotPackageHash,
        ),
        duplicateBallotPolicyHash: ballotSet.duplicateBallotPolicyHash,
        electionManifestHash: ballotSet.electionManifestHash,
        includeRejectedCandidateSummariesInHash:
            ballotSet.includeRejectedCandidateSummariesInHash,
        pollSpecHash: ballotSet.pollSpecHash,
        purpose: 'canonical-ballot-set-v1',
        rejectedCandidates:
            ballotSet.includeRejectedCandidateSummariesInHash === true
                ? ballotSet.rejectedCandidates.map((candidate) => ({
                      ballotPackageHash: candidate.ballotPackageHash,
                      refusalCodes: candidate.refusalCodes,
                      signedBoardOrder: candidate.signedBoardOrder ?? null,
                      voterIdentity: candidate.voterIdentity ?? null,
                  }))
                : [],
        rosterHash: ballotSet.rosterHash,
        thresholdProfileHash: ballotSet.thresholdProfileHash,
        votingClosedBoardHeadHash: ballotSet.votingClosedBoardHeadHash,
    });

const candidateSignedBoardOrder = (
    candidate: BallotPackageCandidate,
): SignedBoardOrder => ({
    boardSequence: candidate.inclusionProof.boardSequence,
    boardPosition: candidate.inclusionProof.boardPosition,
});

const candidateBoardPositionKey = (
    candidate: BallotPackageCandidate,
): string => {
    const signedBoardOrder = candidateSignedBoardOrder(candidate);

    return [
        signedBoardOrder.boardSequence,
        signedBoardOrder.boardPosition,
    ].join('\u0000');
};

const sortCandidateBallots = (
    candidateBallots: readonly BallotPackageCandidate[],
): readonly BallotPackageCandidate[] =>
    [...candidateBallots].sort((left, right) => {
        const leftSignedBoardOrder = candidateSignedBoardOrder(left);
        const rightSignedBoardOrder = candidateSignedBoardOrder(right);

        return (
            compareSignedBoardOrder(
                leftSignedBoardOrder,
                rightSignedBoardOrder,
            ) ||
            compareCanonicalStrings(
                left.ballotPackage.ballotPackageHash,
                right.ballotPackage.ballotPackageHash,
            ) ||
            compareCanonicalStrings(
                left.inclusionProof.inclusionProofHash,
                right.inclusionProof.inclusionProofHash,
            )
        );
    });

// Equivocation detector: a single board position (boardSequence,boardPosition)
// that maps to two or more distinct ballot-package hashes.
const findConflictingBoardPositionKeys = (
    candidateBallots: readonly BallotPackageCandidate[],
): ReadonlySet<string> => {
    const hashesByBoardPosition = new Map<string, Set<ProtocolHash>>();

    for (const candidate of candidateBallots) {
        const key = candidateBoardPositionKey(candidate);
        const hashes =
            hashesByBoardPosition.get(key) ?? new Set<ProtocolHash>();

        hashes.add(candidate.ballotPackage.ballotPackageHash);
        hashesByBoardPosition.set(key, hashes);
    }

    return new Set(
        [...hashesByBoardPosition.entries()]
            .filter((entry) => entry[1].size > 1)
            .map(([key]) => key),
    );
};

// Equivocation detector: one ballot-package hash that resolves to two or more
// distinct canonical package shells (same hash claimed for different content).
const findConflictingBallotPackageHashes = (
    candidateBallots: readonly BallotPackageCandidate[],
): ReadonlySet<ProtocolHash> => {
    const shellsByHash = new Map<ProtocolHash, Set<string>>();

    for (const candidate of candidateBallots) {
        const shells =
            shellsByHash.get(candidate.ballotPackage.ballotPackageHash) ??
            new Set<string>();

        shells.add(canonicalJson(candidate.ballotPackage));
        shellsByHash.set(candidate.ballotPackage.ballotPackageHash, shells);
    }

    return new Set(
        [...shellsByHash.entries()]
            .filter((entry) => entry[1].size > 1)
            .map(([hash]) => hash),
    );
};

const deriveRejectedCandidate = (
    candidate: BallotPackageCandidate,
    refusedObjects: readonly RefusalRecord[],
): RejectedBallotCandidate => ({
    ballotPackageHash: candidate.ballotPackage.ballotPackageHash,
    voterIdentity: candidate.ballotPackage.voterIdentity,
    signedBoardOrder: candidateSignedBoardOrder(candidate),
    refusalCodes: refusedObjects.map((refusal) => refusal.code),
});

type CloseBoundCanonicalBallotSetInput = CanonicalBallotSetInput & {
    readonly closeRecordInclusionProof: InclusionProof;
};

const validateSetInput = (
    input: CloseBoundCanonicalBallotSetInput,
    headsByHash: ReadonlyMap<ProtocolHash, SignedBoardHead>,
): readonly RefusalRecord[] => {
    const closeRecordInclusionProof: InclusionProof =
        input.closeRecordInclusionProof;
    const refusedObjects: RefusalRecord[] = [
        ...validatePollAndThreshold(input.pollSpec, input.thresholdProfile),
        ...validateRosterEntries(input.rosterEntries, input.thresholdProfile),
    ];

    if (
        !isNonNegativeInteger(input.closeRecordBoardOrder.boardSequence) ||
        !isNonNegativeInteger(input.closeRecordBoardOrder.boardPosition)
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotSetInvalid',
                'Ballot-set selection requires a canonical voting-close board order.',
                input.closeRecordHash,
            ),
        );
    }
    if (
        input.boardEvidence.ceremonyId !== input.ceremonyId ||
        input.boardEvidence.signedBoardHeads.every(
            (head) => head.headHash !== input.votingClosedBoardHeadHash,
        )
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotSetInvalid',
                'Ballot-set selection requires board evidence for the voting-close head.',
                input.votingClosedBoardHeadHash,
                'BoardHead',
            ),
        );
    }
    refusedObjects.push(
        ...verifyInclusionProof(closeRecordInclusionProof, headsByHash),
    );
    if (
        closeRecordInclusionProof.includedObjectType !== 'CloseRecord' ||
        closeRecordInclusionProof.includedObjectHash !==
            input.closeRecordHash ||
        closeRecordInclusionProof.boardHeadHash !==
            input.votingClosedBoardHeadHash ||
        closeRecordInclusionProof.boardSequence !==
            input.closeRecordBoardOrder.boardSequence ||
        closeRecordInclusionProof.boardPosition !==
            input.closeRecordBoardOrder.boardPosition
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotSetInvalid',
                'Ballot-set selection requires close-record inclusion evidence that binds the voting-close order.',
                input.closeRecordHash,
                'CloseRecord',
            ),
        );
    }

    return refusedObjects;
};

const deriveCanonicalBallotSetUnchecked = (
    input: CanonicalBallotSetInput,
): CanonicalBallotSet => {
    const boardResult = verifyBoardConsistency(input.boardEvidence);
    const headsByHash = buildBoardHeadMap(input.boardEvidence.signedBoardHeads);
    const fatalRefusals: RefusalRecord[] = [
        ...boardResult.refusedObjects,
        ...validateSetInput(input, headsByHash),
    ];
    const rejectedCandidates: RejectedBallotCandidate[] = [];
    const selectedByVoter = new Map<string, CountedBallotPackage>();
    const seenValidBallotPackageHashes = new Set<ProtocolHash>();
    const conflictingBoardPositionKeys = findConflictingBoardPositionKeys(
        input.candidateBallots,
    );
    const conflictingBallotPackageHashes = findConflictingBallotPackageHashes(
        input.candidateBallots,
    );

    // Duplicate policy "first valid before voting closed counts": iterate in
    // canonical board order, and for each voter keep only the first valid
    // ballot; later valid ballots from the same voter are recorded as
    // duplicate-not-counted. The canonical ordering makes this deterministic.
    for (const candidate of sortCandidateBallots(input.candidateBallots)) {
        const candidateRefusals: RefusalRecord[] = [];
        const signedBoardOrder = candidateSignedBoardOrder(candidate);
        const boardPositionKey = candidateBoardPositionKey(candidate);

        if (conflictingBoardPositionKeys.has(boardPositionKey)) {
            candidateRefusals.push(
                createRefusal(
                    'ConflictingBallotPackage',
                    'Two non-identical ballot package candidates claim the same board position.',
                    candidate.ballotPackage.ballotPackageHash,
                    'BallotPackage',
                ),
            );
        }
        if (
            conflictingBallotPackageHashes.has(
                candidate.ballotPackage.ballotPackageHash,
            )
        ) {
            candidateRefusals.push(
                createRefusal(
                    'ConflictingBallotPackage',
                    'Two non-identical ballot package candidates claim the same package hash.',
                    candidate.ballotPackage.ballotPackageHash,
                    'BallotPackage',
                ),
            );
        }

        candidateRefusals.push(
            ...verifyInclusionProof(candidate.inclusionProof, headsByHash),
        );
        if (
            candidate.inclusionProof.includedObjectType !== 'BallotPackage' ||
            candidate.inclusionProof.includedObjectHash !==
                candidate.ballotPackage.ballotPackageHash
        ) {
            candidateRefusals.push(
                createRefusal(
                    'InclusionProofInvalid',
                    'Ballot package inclusion proof must bind the ballot package hash.',
                    candidate.inclusionProof.inclusionProofHash,
                    'BallotPackage',
                ),
            );
        }
        if (
            !isBeforeSignedBoardOrder(
                signedBoardOrder,
                input.closeRecordBoardOrder,
            )
        ) {
            candidateRefusals.push(
                createRefusal(
                    'BallotPackageInvalid',
                    'Ballot package was not included before voting closed.',
                    candidate.ballotPackage.ballotPackageHash,
                    'BallotPackage',
                ),
            );
        }
        candidateRefusals.push(
            ...verifyBallotPackageShell({
                ballotPackage: candidate.ballotPackage,
                ceremonyId: input.ceremonyId,
                electionManifestHash: input.electionManifestHash,
                rosterHash: input.rosterHash,
                pollSpecHash: input.pollSpecHash,
                thresholdProfileHash: input.thresholdProfileHash,
                duplicateBallotPolicyHash: input.duplicateBallotPolicyHash,
                optionCount: input.pollSpec.options.length,
                rosterEntries: input.rosterEntries,
                thresholdProfile: input.thresholdProfile,
            }),
        );

        if (candidateRefusals.length > 0) {
            rejectedCandidates.push(
                deriveRejectedCandidate(candidate, candidateRefusals),
            );
            continue;
        }
        if (
            seenValidBallotPackageHashes.has(
                candidate.ballotPackage.ballotPackageHash,
            )
        ) {
            continue;
        }
        seenValidBallotPackageHashes.add(
            candidate.ballotPackage.ballotPackageHash,
        );

        const validCandidate = {
            ...candidate,
            signedBoardOrder,
        };

        if (selectedByVoter.has(candidate.ballotPackage.voterIdentity)) {
            rejectedCandidates.push(
                deriveRejectedCandidate(candidate, [
                    createRefusal(
                        'DuplicateBallotPackage',
                        'Later valid ballot from the same voter is duplicate evidence and is not counted.',
                        candidate.ballotPackage.ballotPackageHash,
                        'BallotPackage',
                    ),
                ]),
            );
            continue;
        }

        selectedByVoter.set(
            candidate.ballotPackage.voterIdentity,
            validCandidate,
        );
    }

    const countedBallots = [...selectedByVoter.values()].sort(
        (left, right) =>
            compareSignedBoardOrder(
                left.signedBoardOrder,
                right.signedBoardOrder,
            ) ||
            compareCanonicalStrings(
                left.ballotPackage.ballotPackageHash,
                right.ballotPackage.ballotPackageHash,
            ),
    );
    const ok = fatalRefusals.length === 0;
    const ballotSetHash = ok
        ? deriveBallotSetHash({
              base: input,
              countedBallots,
              rejectedCandidates,
          })
        : undefined;

    return {
        ok,
        statusLabels: boardResult.statusLabels,
        acceptedHashes:
            ballotSetHash === undefined
                ? []
                : uniqueStrings([
                      ...boardResult.acceptedHashes,
                      ballotSetHash,
                      ...countedBallots.map(
                          (candidate) =>
                              candidate.ballotPackage.ballotPackageHash,
                      ),
                  ]),
        refusedObjects: fatalRefusals,
        ceremonyId: input.ceremonyId,
        electionManifestHash: input.electionManifestHash,
        rosterHash: input.rosterHash,
        pollSpecHash: input.pollSpecHash,
        thresholdProfileHash: input.thresholdProfileHash,
        duplicateBallotPolicyHash: input.duplicateBallotPolicyHash,
        votingClosedBoardHeadHash: input.votingClosedBoardHeadHash,
        closeRecordHash: input.closeRecordHash,
        includeRejectedCandidateSummariesInHash:
            input.includeRejectedCandidateSummariesInHash === true,
        countedBallots,
        rejectedCandidates,
        ballotSetHash,
    };
};

export const deriveCanonicalBallotSet = (
    input: CanonicalBallotSetInput,
): CanonicalBallotSet => {
    try {
        return deriveCanonicalBallotSetUnchecked(input);
    } catch {
        return {
            ok: false,
            statusLabels: [],
            acceptedHashes: [],
            refusedObjects: [
                createRefusal(
                    'BallotSetInvalid',
                    'Canonical ballot-set input could not be canonicalized or validated.',
                ),
            ],
            ceremonyId: input.ceremonyId,
            electionManifestHash: input.electionManifestHash,
            rosterHash: input.rosterHash,
            pollSpecHash: input.pollSpecHash,
            thresholdProfileHash: input.thresholdProfileHash,
            duplicateBallotPolicyHash: input.duplicateBallotPolicyHash,
            votingClosedBoardHeadHash: input.votingClosedBoardHeadHash,
            closeRecordHash: input.closeRecordHash,
            includeRejectedCandidateSummariesInHash:
                input.includeRejectedCandidateSummariesInHash === true,
            countedBallots: [],
            rejectedCandidates: [],
        };
    }
};

import { canonicalJson, deriveProtocolDigest } from '@sealed-lattice/crypto';
import type {
    BallotPackageCandidate,
    CanonicalBallotSet,
    CanonicalBallotSetInput,
    CountedBallotPackage,
    InclusionProof,
    ProtocolDigest,
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

const deriveBallotSetDigest = (input: {
    readonly base: CanonicalBallotSetInput;
    readonly countedBallots: readonly CountedBallotPackage[];
    readonly rejectedCandidates: readonly RejectedBallotCandidate[];
}): ProtocolDigest =>
    deriveProtocolDigest('BallotSetDigest', {
        ceremonyId: input.base.ceremonyId,
        closeRecordDigest: input.base.closeRecordDigest,
        countedBallotPackageDigests: input.countedBallots.map(
            (candidate) => candidate.ballotPackage.ballotPackageDigest,
        ),
        duplicateBallotPolicyDigest: input.base.duplicateBallotPolicyDigest,
        electionManifestDigest: input.base.electionManifestDigest,
        pollSpecDigest: input.base.pollSpecDigest,
        includeRejectedCandidateSummariesInDigest:
            input.base.includeRejectedCandidateSummariesInDigest === true,
        rejectedCandidates:
            input.base.includeRejectedCandidateSummariesInDigest === true
                ? input.rejectedCandidates.map((candidate) => ({
                      ballotPackageDigest: candidate.ballotPackageDigest,
                      refusalCodes: candidate.refusalCodes,
                      signedBoardOrder: candidate.signedBoardOrder ?? null,
                      voterIdentity: candidate.voterIdentity ?? null,
                  }))
                : [],
        rosterDigest: input.base.rosterDigest,
        thresholdProfileDigest: input.base.thresholdProfileDigest,
        votingClosedBoardHeadDigest: input.base.votingClosedBoardHeadDigest,
    });

export const deriveBallotSetDigestFromCanonicalSet = (
    ballotSet: Pick<
        CanonicalBallotSet,
        | 'ceremonyId'
        | 'closeRecordDigest'
        | 'countedBallots'
        | 'duplicateBallotPolicyDigest'
        | 'electionManifestDigest'
        | 'includeRejectedCandidateSummariesInDigest'
        | 'pollSpecDigest'
        | 'rejectedCandidates'
        | 'rosterDigest'
        | 'thresholdProfileDigest'
        | 'votingClosedBoardHeadDigest'
    >,
): ProtocolDigest =>
    deriveProtocolDigest('BallotSetDigest', {
        ceremonyId: ballotSet.ceremonyId,
        closeRecordDigest: ballotSet.closeRecordDigest,
        countedBallotPackageDigests: ballotSet.countedBallots.map(
            (candidate) => candidate.ballotPackage.ballotPackageDigest,
        ),
        duplicateBallotPolicyDigest: ballotSet.duplicateBallotPolicyDigest,
        electionManifestDigest: ballotSet.electionManifestDigest,
        includeRejectedCandidateSummariesInDigest:
            ballotSet.includeRejectedCandidateSummariesInDigest,
        pollSpecDigest: ballotSet.pollSpecDigest,
        rejectedCandidates:
            ballotSet.includeRejectedCandidateSummariesInDigest === true
                ? ballotSet.rejectedCandidates.map((candidate) => ({
                      ballotPackageDigest: candidate.ballotPackageDigest,
                      refusalCodes: candidate.refusalCodes,
                      signedBoardOrder: candidate.signedBoardOrder ?? null,
                      voterIdentity: candidate.voterIdentity ?? null,
                  }))
                : [],
        rosterDigest: ballotSet.rosterDigest,
        thresholdProfileDigest: ballotSet.thresholdProfileDigest,
        votingClosedBoardHeadDigest: ballotSet.votingClosedBoardHeadDigest,
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
                left.ballotPackage.ballotPackageDigest,
                right.ballotPackage.ballotPackageDigest,
            ) ||
            compareCanonicalStrings(
                left.inclusionProof.inclusionProofDigest,
                right.inclusionProof.inclusionProofDigest,
            )
        );
    });

const findConflictingBoardPositionKeys = (
    candidateBallots: readonly BallotPackageCandidate[],
): ReadonlySet<string> => {
    const digestsByBoardPosition = new Map<string, Set<ProtocolDigest>>();

    for (const candidate of candidateBallots) {
        const key = candidateBoardPositionKey(candidate);
        const digests =
            digestsByBoardPosition.get(key) ?? new Set<ProtocolDigest>();

        digests.add(candidate.ballotPackage.ballotPackageDigest);
        digestsByBoardPosition.set(key, digests);
    }

    return new Set(
        [...digestsByBoardPosition.entries()]
            .filter((entry) => entry[1].size > 1)
            .map(([key]) => key),
    );
};

const findConflictingBallotPackageDigests = (
    candidateBallots: readonly BallotPackageCandidate[],
): ReadonlySet<ProtocolDigest> => {
    const shellsByDigest = new Map<ProtocolDigest, Set<string>>();

    for (const candidate of candidateBallots) {
        const shells =
            shellsByDigest.get(candidate.ballotPackage.ballotPackageDigest) ??
            new Set<string>();

        shells.add(canonicalJson(candidate.ballotPackage));
        shellsByDigest.set(candidate.ballotPackage.ballotPackageDigest, shells);
    }

    return new Set(
        [...shellsByDigest.entries()]
            .filter((entry) => entry[1].size > 1)
            .map(([digest]) => digest),
    );
};

const deriveRejectedCandidate = (
    candidate: BallotPackageCandidate,
    refusedObjects: readonly RefusalRecord[],
): RejectedBallotCandidate => ({
    ballotPackageDigest: candidate.ballotPackage.ballotPackageDigest,
    voterIdentity: candidate.ballotPackage.voterIdentity,
    signedBoardOrder: candidateSignedBoardOrder(candidate),
    refusalCodes: refusedObjects.map((refusal) => refusal.code),
});

type CloseBoundCanonicalBallotSetInput = CanonicalBallotSetInput & {
    readonly closeRecordInclusionProof: InclusionProof;
};

const validateSetInput = (
    input: CloseBoundCanonicalBallotSetInput,
    headsByDigest: ReadonlyMap<ProtocolDigest, SignedBoardHead>,
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
                input.closeRecordDigest,
            ),
        );
    }
    if (
        input.boardEvidence.ceremonyId !== input.ceremonyId ||
        input.boardEvidence.signedBoardHeads.every(
            (head) => head.headDigest !== input.votingClosedBoardHeadDigest,
        )
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotSetInvalid',
                'Ballot-set selection requires board evidence for the voting-close head.',
                input.votingClosedBoardHeadDigest,
                'BoardHead',
            ),
        );
    }
    refusedObjects.push(
        ...verifyInclusionProof(closeRecordInclusionProof, headsByDigest),
    );
    if (
        closeRecordInclusionProof.includedObjectType !== 'CloseRecord' ||
        closeRecordInclusionProof.includedObjectDigest !==
            input.closeRecordDigest ||
        closeRecordInclusionProof.boardHeadDigest !==
            input.votingClosedBoardHeadDigest ||
        closeRecordInclusionProof.boardSequence !==
            input.closeRecordBoardOrder.boardSequence ||
        closeRecordInclusionProof.boardPosition !==
            input.closeRecordBoardOrder.boardPosition
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotSetInvalid',
                'Ballot-set selection requires close-record inclusion evidence that binds the voting-close order.',
                input.closeRecordDigest,
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
    const headsByDigest = buildBoardHeadMap(
        input.boardEvidence.signedBoardHeads,
    );
    const fatalRefusals: RefusalRecord[] = [
        ...boardResult.refusedObjects,
        ...validateSetInput(input, headsByDigest),
    ];
    const validCandidates: CountedBallotPackage[] = [];
    const rejectedCandidates: RejectedBallotCandidate[] = [];
    const seenValidBallotPackageDigests = new Set<ProtocolDigest>();
    const conflictingBoardPositionKeys = findConflictingBoardPositionKeys(
        input.candidateBallots,
    );
    const conflictingBallotPackageDigests = findConflictingBallotPackageDigests(
        input.candidateBallots,
    );

    for (const candidate of sortCandidateBallots(input.candidateBallots)) {
        const candidateRefusals: RefusalRecord[] = [];
        const signedBoardOrder = candidateSignedBoardOrder(candidate);
        const boardPositionKey = candidateBoardPositionKey(candidate);

        if (conflictingBoardPositionKeys.has(boardPositionKey)) {
            candidateRefusals.push(
                createRefusal(
                    'ConflictingBallotPackage',
                    'Two non-identical ballot package candidates claim the same board position.',
                    candidate.ballotPackage.ballotPackageDigest,
                    'BallotPackage',
                ),
            );
        }
        if (
            conflictingBallotPackageDigests.has(
                candidate.ballotPackage.ballotPackageDigest,
            )
        ) {
            candidateRefusals.push(
                createRefusal(
                    'ConflictingBallotPackage',
                    'Two non-identical ballot package candidates claim the same package digest.',
                    candidate.ballotPackage.ballotPackageDigest,
                    'BallotPackage',
                ),
            );
        }

        candidateRefusals.push(
            ...verifyInclusionProof(candidate.inclusionProof, headsByDigest),
        );
        if (
            candidate.inclusionProof.includedObjectType !== 'BallotPackage' ||
            candidate.inclusionProof.includedObjectDigest !==
                candidate.ballotPackage.ballotPackageDigest
        ) {
            candidateRefusals.push(
                createRefusal(
                    'InclusionProofInvalid',
                    'Ballot package inclusion proof must bind the ballot package digest.',
                    candidate.inclusionProof.inclusionProofDigest,
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
                    candidate.ballotPackage.ballotPackageDigest,
                    'BallotPackage',
                ),
            );
        }
        candidateRefusals.push(
            ...verifyBallotPackageShell({
                ballotPackage: candidate.ballotPackage,
                ceremonyId: input.ceremonyId,
                electionManifestDigest: input.electionManifestDigest,
                rosterDigest: input.rosterDigest,
                pollSpecDigest: input.pollSpecDigest,
                thresholdProfileDigest: input.thresholdProfileDigest,
                duplicateBallotPolicyDigest: input.duplicateBallotPolicyDigest,
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
            seenValidBallotPackageDigests.has(
                candidate.ballotPackage.ballotPackageDigest,
            )
        ) {
            continue;
        }
        seenValidBallotPackageDigests.add(
            candidate.ballotPackage.ballotPackageDigest,
        );

        validCandidates.push({
            ...candidate,
            signedBoardOrder,
        });
    }

    const selectedByVoter = new Map<string, CountedBallotPackage>();
    for (const candidate of validCandidates.sort(
        (left, right) =>
            compareSignedBoardOrder(
                left.signedBoardOrder,
                right.signedBoardOrder,
            ) ||
            compareCanonicalStrings(
                left.ballotPackage.ballotPackageDigest,
                right.ballotPackage.ballotPackageDigest,
            ),
    )) {
        selectedByVoter.set(candidate.ballotPackage.voterIdentity, candidate);
    }
    const countedBallots = [...selectedByVoter.values()].sort(
        (left, right) =>
            compareSignedBoardOrder(
                left.signedBoardOrder,
                right.signedBoardOrder,
            ) ||
            compareCanonicalStrings(
                left.ballotPackage.ballotPackageDigest,
                right.ballotPackage.ballotPackageDigest,
            ),
    );
    const ok = fatalRefusals.length === 0;
    const ballotSetDigest = ok
        ? deriveBallotSetDigest({
              base: input,
              countedBallots,
              rejectedCandidates,
          })
        : undefined;

    return {
        ok,
        statusLabels: boardResult.statusLabels,
        acceptedDigests:
            ballotSetDigest === undefined
                ? []
                : uniqueStrings([
                      ...boardResult.acceptedDigests,
                      ballotSetDigest,
                      ...countedBallots.map(
                          (candidate) =>
                              candidate.ballotPackage.ballotPackageDigest,
                      ),
                  ]),
        refusedObjects: fatalRefusals,
        ceremonyId: input.ceremonyId,
        electionManifestDigest: input.electionManifestDigest,
        rosterDigest: input.rosterDigest,
        pollSpecDigest: input.pollSpecDigest,
        thresholdProfileDigest: input.thresholdProfileDigest,
        duplicateBallotPolicyDigest: input.duplicateBallotPolicyDigest,
        votingClosedBoardHeadDigest: input.votingClosedBoardHeadDigest,
        closeRecordDigest: input.closeRecordDigest,
        includeRejectedCandidateSummariesInDigest:
            input.includeRejectedCandidateSummariesInDigest === true,
        countedBallots,
        rejectedCandidates,
        ballotSetDigest,
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
            acceptedDigests: [],
            refusedObjects: [
                createRefusal(
                    'BallotSetInvalid',
                    'Canonical ballot-set input could not be canonicalized or validated.',
                ),
            ],
            ceremonyId: input.ceremonyId,
            electionManifestDigest: input.electionManifestDigest,
            rosterDigest: input.rosterDigest,
            pollSpecDigest: input.pollSpecDigest,
            thresholdProfileDigest: input.thresholdProfileDigest,
            duplicateBallotPolicyDigest: input.duplicateBallotPolicyDigest,
            votingClosedBoardHeadDigest: input.votingClosedBoardHeadDigest,
            closeRecordDigest: input.closeRecordDigest,
            includeRejectedCandidateSummariesInDigest:
                input.includeRejectedCandidateSummariesInDigest === true,
            countedBallots: [],
            rejectedCandidates: [],
        };
    }
};

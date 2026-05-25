import { deriveProtocolDigest } from '@sealed-lattice/crypto';
import type {
    AggregateDerivationComponent,
    AggregateDerivationProofRecord,
    AggregateDerivationStatement,
    AggregateShareCommitment,
    ProtocolDigest,
} from '@sealed-lattice/types';

import { aggregateDerivationComponentId } from './constants.js';
import type { AggregateDerivationProofStatement } from './types.js';

export const deriveAggregateCommitmentBodyDigest = (input: {
    readonly commitmentPolynomialVector: readonly (readonly string[])[];
    readonly shareCommitmentProfileDigest: ProtocolDigest;
}): ProtocolDigest =>
    deriveProtocolDigest('AggregateShareCommitmentDigest', {
        commitmentPolynomialVector: input.commitmentPolynomialVector,
        profileDigest: input.shareCommitmentProfileDigest,
        purpose: 'aggregate-share-commitment-body-v1',
    });

export const deriveAggregateShareCommitmentDigest = (
    aggregateCommitment: Omit<
        AggregateShareCommitment,
        'aggregateShareCommitmentDigest'
    >,
): ProtocolDigest =>
    deriveProtocolDigest('AggregateShareCommitmentDigest', aggregateCommitment);

export const deriveAggregateDerivationStatementDigest = (
    statement: Omit<
        AggregateDerivationStatement,
        'aggregateDerivationStatementDigest'
    >,
): ProtocolDigest =>
    deriveProtocolDigest('AggregateDerivationComponentDigest', {
        purpose: 'aggregate-derivation-statement-v1',
        statement,
    });

export const deriveAggregateDerivationProofRecordDigest = (
    proofRecord: Omit<
        AggregateDerivationProofRecord,
        'aggregateDerivationProofRecordDigest'
    >,
): ProtocolDigest =>
    deriveProtocolDigest('AggregateDerivationComponentDigest', {
        proofRecord,
        purpose: 'aggregate-derivation-proof-record-v1',
    });

export const deriveAggregateDerivationComponentDigest = (
    component: Omit<
        AggregateDerivationComponent,
        'aggregateDerivationComponentDigest'
    >,
): ProtocolDigest =>
    deriveProtocolDigest('AggregateDerivationComponentDigest', {
        component,
        purpose: 'aggregate-derivation-component-v1',
    });

export const deriveAggregateSparseLinearStatementDigest = (
    statementPayload: Omit<
        AggregateDerivationProofStatement,
        'statementDigest'
    >,
): ProtocolDigest =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        payload: statementPayload,
        purpose: 'aggregate-derivation-sparse-linear-proof-statement-v1',
    });

export const deriveAggregateDerivationProofRoot = (input: {
    readonly componentProofStatementDigest: ProtocolDigest;
    readonly proofBytesDigest: ProtocolDigest;
    readonly proofEncodingProfileDigest: ProtocolDigest;
    readonly proofParameterSetDigest: ProtocolDigest;
    readonly publicRandomnessDigest: ProtocolDigest;
    readonly statementDigest: ProtocolDigest;
}): ProtocolDigest =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        ...input,
        componentId: aggregateDerivationComponentId,
        purpose: 'aggregate-derivation-proof-root-v1',
    });

export const deriveAggregateDerivationBallotSetDigest = (input: {
    readonly ballotPackageDigests: readonly ProtocolDigest[];
    readonly closeRecordDigest: ProtocolDigest;
    readonly manifestDigest: ProtocolDigest;
    readonly pollSpecDigest: ProtocolDigest;
    readonly postVotingClosedContextDigest: ProtocolDigest;
    readonly rosterDigest: ProtocolDigest;
    readonly thresholdProfileDigest: ProtocolDigest;
    readonly votingClosedBoardHeadDigest: ProtocolDigest;
}): ProtocolDigest =>
    deriveProtocolDigest('BallotSetDigest', {
        ballotPackageDigests: input.ballotPackageDigests,
        closeRecordDigest: input.closeRecordDigest,
        manifestDigest: input.manifestDigest,
        pollSpecDigest: input.pollSpecDigest,
        postVotingClosedContextDigest: input.postVotingClosedContextDigest,
        purpose: 'm6-post-close-counted-m5-ballot-set-v1',
        rosterDigest: input.rosterDigest,
        thresholdProfileDigest: input.thresholdProfileDigest,
        votingClosedBoardHeadDigest: input.votingClosedBoardHeadDigest,
    });

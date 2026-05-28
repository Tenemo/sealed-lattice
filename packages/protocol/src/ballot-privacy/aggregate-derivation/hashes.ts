import { deriveProtocolHash } from '@sealed-lattice/crypto';
import type {
    AggregateDerivationComponent,
    AggregateDerivationProofRecord,
    AggregateDerivationStatement,
    AggregateShareCommitment,
    ProtocolHash,
} from '@sealed-lattice/types';

import { aggregateDerivationComponentId } from './constants.js';
import type { AggregateDerivationProofStatement } from './types.js';

export const deriveAggregateCommitmentBodyHash = (input: {
    readonly commitmentPolynomialVector: readonly (readonly string[])[];
    readonly shareCommitmentProfileHash: ProtocolHash;
}): ProtocolHash =>
    deriveProtocolHash('AggregateShareCommitmentHash', {
        commitmentPolynomialVector: input.commitmentPolynomialVector,
        profileHash: input.shareCommitmentProfileHash,
        purpose: 'aggregate-share-commitment-body-v1',
    });

export const deriveAggregateShareCommitmentHash = (
    aggregateCommitment: Omit<
        AggregateShareCommitment,
        'aggregateShareCommitmentHash'
    >,
): ProtocolHash =>
    deriveProtocolHash('AggregateShareCommitmentHash', aggregateCommitment);

export const deriveAggregateDerivationStatementHash = (
    statement: Omit<
        AggregateDerivationStatement,
        'aggregateDerivationStatementHash'
    >,
): ProtocolHash =>
    deriveProtocolHash('AggregateDerivationComponentHash', {
        purpose: 'aggregate-derivation-statement-v1',
        statement,
    });

export const deriveAggregateDerivationProofRecordHash = (
    proofRecord: Omit<
        AggregateDerivationProofRecord,
        'aggregateDerivationProofRecordHash'
    >,
): ProtocolHash =>
    deriveProtocolHash('AggregateDerivationComponentHash', {
        proofRecord,
        purpose: 'aggregate-derivation-proof-record-v1',
    });

export const deriveAggregateDerivationComponentHash = (
    component: Omit<
        AggregateDerivationComponent,
        'aggregateDerivationComponentHash'
    >,
): ProtocolHash =>
    deriveProtocolHash('AggregateDerivationComponentHash', {
        component,
        purpose: 'aggregate-derivation-component-v1',
    });

export const deriveAggregateSparseLinearStatementHash = (
    statementPayload: Omit<AggregateDerivationProofStatement, 'statementHash'>,
): ProtocolHash =>
    deriveProtocolHash('ChallengeDomainHash', {
        payload: statementPayload,
        purpose: 'aggregate-derivation-sparse-linear-proof-statement-v1',
    });

export const deriveAggregateDerivationProofRoot = (input: {
    readonly componentProofStatementHash: ProtocolHash;
    readonly proofBytesHash: ProtocolHash;
    readonly proofEncodingProfileHash: ProtocolHash;
    readonly proofParameterSetHash: ProtocolHash;
    readonly publicRandomnessHash: ProtocolHash;
    readonly statementHash: ProtocolHash;
}): ProtocolHash =>
    deriveProtocolHash('ChallengeDomainHash', {
        ...input,
        componentId: aggregateDerivationComponentId,
        purpose: 'aggregate-derivation-proof-root-v1',
    });

export const deriveAggregateDerivationBallotSetHash = (input: {
    readonly ballotPackageHashes: readonly ProtocolHash[];
    readonly closeRecordHash: ProtocolHash;
    readonly manifestHash: ProtocolHash;
    readonly pollSpecHash: ProtocolHash;
    readonly postVotingClosedContextHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly thresholdProfileHash: ProtocolHash;
    readonly votingClosedBoardHeadHash: ProtocolHash;
}): ProtocolHash =>
    deriveProtocolHash('BallotSetHash', {
        ballotPackageHashes: input.ballotPackageHashes,
        closeRecordHash: input.closeRecordHash,
        manifestHash: input.manifestHash,
        pollSpecHash: input.pollSpecHash,
        postVotingClosedContextHash: input.postVotingClosedContextHash,
        purpose: 'm6-post-close-counted-m5-ballot-set-v1',
        rosterHash: input.rosterHash,
        thresholdProfileHash: input.thresholdProfileHash,
        votingClosedBoardHeadHash: input.votingClosedBoardHeadHash,
    });

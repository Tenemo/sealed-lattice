import type { ProtocolDigest, RefusalRecord } from '@sealed-lattice/types';

import { createRefusal } from '../../common/verification-helpers.js';

export const aggregateDerivationComponentId =
    'aggregate-derivation-component' as const;

export const aggregateDerivationSourceRingDegree = 256 as const;

export const aggregateDerivationProofSystemRingDegree = 64 as const;

export const aggregateDerivationProofCoefficientModulus =
    '70368744177829' as const;

export const aggregateDerivationWitnessL2BoundSquared =
    3_000_000_000_000_000 as const;

export const protocolDigestPattern = /^[a-f0-9]{128}$/u;

export const lowercaseHexBytesPattern = /^(?:[a-f0-9]{2})+$/u;

export const forbiddenPublicWitnessFieldNames = new Set([
    'aggregateIntegerShareVector',
    'aggregateHistogram',
    'aggregateOpeningRandomness',
    'aggregateScore',
    'aggregateScoreBits',
    'aggregateShareVector',
    'bgvPlaintext',
    'bridgeWitness',
    'encryptionError',
    'encryptionNoise',
    'encryptionRandomness',
    'errorNoise',
    'openingRandomness',
    'plaintext',
    'plaintextComparisonInputs',
    'plaintextScoreBitInputs',
    'proofWitness',
    'quotient',
    'rawAggregateWitness',
    'receiverPlaintext',
    'receiverSecretState',
    'reducedFieldVector',
    'secretState',
    'sourceWitnessCoefficients',
    'aggregateInputPlaintext',
    'layoutPlaintextWitness',
    'tPvss',
    't_pvss',
    'witness',
]);

export const createAggregateRefusal = (
    message: string,
    objectDigest?: ProtocolDigest,
): RefusalRecord =>
    createRefusal('BallotPackageInvalid', message, objectDigest);

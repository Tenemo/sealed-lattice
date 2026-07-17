import type { ProtocolHash, VerificationResult } from '@sealed-lattice/types';

export type BgvRnsParametersDescription = {
    readonly parameters: {
        readonly polynomialDegree: number;
        readonly plaintextModulus: number;
        readonly dataPrimes: readonly number[];
        readonly specialPrimes: readonly number[];
        readonly scoreRange: {
            readonly minimum: number;
            readonly maximum: number;
        };
        readonly bucketCount: number;
        readonly coordinatesPerOption: number;
    };
    readonly bgvParametersHash: ProtocolHash;
};

export type BgvCollectiveSetupParametersDescription = {
    readonly setupParametersHash: ProtocolHash;
    readonly participantCount: number;
    readonly reconstructionThreshold: number;
    readonly qShare: {
        readonly primes: readonly number[];
    };
    readonly evaluatorKeySchedule: {
        readonly objectType: 'EvaluatorKeySchedule';
        readonly relinearizationLevelSchedule: readonly {
            readonly level: number;
        }[];
        readonly requiredGaloisKeySchedule: readonly {
            readonly rotation: number;
            readonly level: number;
        }[];
    };
    readonly boundedDomainEvaluator: {
        readonly objectType: 'BoundedDomainEvaluatorParameters';
        readonly scoreDifferenceBound: number;
        readonly directComparisonOutputLevel: number;
    };
};

export type BgvCollectiveSetupVerification = VerificationResult<void>;

export type BgvPrivateVssShareEnvelopeVerification = VerificationResult<{
    readonly privateEnvelopeHash: ProtocolHash;
}>;

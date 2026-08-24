import type { ProtocolHash } from '@sealed-lattice/types';

export type BgvRnsParametersDescription = {
    readonly parameters: {
        readonly polynomialDegree: number;
        readonly plaintextModulus: string;
        readonly dataPrimes: readonly string[];
        readonly specialPrimes: readonly string[];
        readonly nttRootParameters: readonly {
            readonly modulus: string;
            readonly primitiveGenerator: string;
            readonly negacyclicRoot: string;
            readonly cyclicRoot: string;
            readonly inverseNegacyclicRoot: string;
            readonly inverseCyclicRoot: string;
            readonly inversePolynomialDegree: string;
        }[];
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
        readonly primes: readonly string[];
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
        readonly pairCharacterOutputLevel: number;
    };
};

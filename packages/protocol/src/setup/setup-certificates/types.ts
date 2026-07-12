import type { ProtocolHash } from '@sealed-lattice/types';

export type JsonRecord = Record<string, unknown>;

export type CollectiveBgvSetupParametersForCertificates = Readonly<
    JsonRecord & {
        readonly setupParametersHash: ProtocolHash;
        readonly participantCount: number;
        readonly qDec: number;
        readonly qShare: Readonly<
            JsonRecord & {
                readonly primes: readonly number[];
            }
        >;
        readonly commitment: Readonly<
            JsonRecord & {
                readonly messageEncoding: JsonRecord;
            }
        >;
        readonly setupProof: JsonRecord;
        readonly setupTransport: JsonRecord;
        readonly evaluatorKeySchedule: Readonly<
            JsonRecord & {
                readonly relinearizationLevelSchedule: readonly Readonly<{
                    readonly level: number;
                }>[];
                readonly requiredGaloisKeySchedule: readonly Readonly<{
                    readonly level: number;
                }>[];
            }
        >;
    }
>;

export type BgvRnsParametersForCertificates = Readonly<
    JsonRecord & {
        readonly parameters: Readonly<
            JsonRecord & {
                readonly polynomialDegree: number;
                readonly plaintextModulus: number;
                readonly dataPrimes: readonly number[];
                readonly specialPrime: number;
            }
        >;
        readonly bgvParametersHash: ProtocolHash;
    }
>;

export type SetupCertificateTransportedObjectInput = Readonly<{
    readonly objectName: string;
    readonly objectRole: string;
    readonly objectRoot: ProtocolHash;
    readonly byteLength: number;
    readonly fullObjectHash: ProtocolHash;
    readonly chunkRoot: ProtocolHash;
    readonly chunkHashes: readonly ProtocolHash[];
}>;

export type SetupCertificateTransportInput = Readonly<{
    readonly fullObjectHash: ProtocolHash;
    readonly chunkHashes: readonly ProtocolHash[];
    readonly transportedObjects?: readonly SetupCertificateTransportedObjectInput[];
}>;

export type SetupCertificatesInput = Readonly<{
    readonly setupParameters:
        | CollectiveBgvSetupParametersForCertificates
        | JsonRecord;
    readonly bgvParameters: BgvRnsParametersForCertificates | JsonRecord;
    readonly transport: SetupCertificateTransportInput;
}>;

export type SetupTransportCertificate = Readonly<
    JsonRecord & {
        readonly objectType: 'SetupTransportCertificate';
        readonly setupTransportCertificateHash: ProtocolHash;
    }
>;

export type SetupTransportCertificateBody = Readonly<
    JsonRecord & {
        readonly objectType: 'SetupTransportCertificate';
    }
>;

export type SetupCertificates = Readonly<{
    readonly setupTransportCertificate: SetupTransportCertificate;
}>;

export type SetupTransportedObjectRecord = Readonly<{
    readonly objectType: 'SetupTransportedObject';
    readonly objectName: string;
    readonly objectRole: string;
    readonly objectRoot: ProtocolHash;
    readonly byteLength: number;
    readonly chunkStartIndex: number;
    readonly chunkCount: number;
    readonly chunkRoot: ProtocolHash;
    readonly chunkHashes: readonly ProtocolHash[];
    readonly fullObjectHash: ProtocolHash;
    readonly encoding: 'binary';
}>;

import type {
    ProtocolHash,
    ProtocolSignatureEnvelope,
} from '@sealed-lattice/types';

import type { JsonRecord } from './common-fields.js';

type CommonRandomnessContextFields = Readonly<{
    readonly ceremonyId: string;
    readonly manifestHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly setupParametersHash: ProtocolHash;
    readonly setupEpoch: string;
}>;

type CommonRandomnessReveal = Readonly<
    JsonRecord &
        CommonRandomnessContextFields & {
            readonly objectType: 'CommonRandomnessReveal';
            readonly trusteeIdentity: string;
            readonly rosterPosition: number;
            readonly recoveryEpoch: number;
            readonly deviceEpoch: number;
            readonly revealHex: string;
            readonly signatureEnvelope: ProtocolSignatureEnvelope;
            readonly revealHash: ProtocolHash;
        }
>;

type CommonRandomnessCommit = Readonly<
    JsonRecord &
        CommonRandomnessContextFields & {
            readonly objectType: 'CommonRandomnessCommit';
            readonly trusteeIdentity: string;
            readonly rosterPosition: number;
            readonly recoveryEpoch: number;
            readonly deviceEpoch: number;
            readonly revealHash: ProtocolHash;
            readonly signatureEnvelope: ProtocolSignatureEnvelope;
            readonly commitHash: ProtocolHash;
        }
>;

type SetupCommonRandomnessPublicDerivations = Readonly<
    JsonRecord & {
        readonly objectType: 'SetupPublicDerivations';
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly bgvPublicA: Readonly<
            JsonRecord & {
                readonly objectType: 'BgvPublicAPolynomial';
                readonly publicMatrixSeedHash: ProtocolHash;
                readonly publicPolynomialRoot: ProtocolHash;
            }
        >;
        readonly crpRoots: Readonly<{
            readonly publicKeyCrpRoot: ProtocolHash;
            readonly relinearizationCrpRoot: ProtocolHash;
            readonly galoisKeyCrpRoot: ProtocolHash;
        }>;
    }
>;

export type SetupCommonRandomness = Readonly<
    JsonRecord &
        CommonRandomnessContextFields & {
            readonly objectType: 'SetupCommonRandomness';
            readonly commitRecords: readonly CommonRandomnessCommit[];
            readonly revealRecords: readonly CommonRandomnessReveal[];
            readonly publicMatrixSeedHash: ProtocolHash;
            readonly publicDerivations: SetupCommonRandomnessPublicDerivations;
            readonly commonRandomnessRoot: ProtocolHash;
        }
>;

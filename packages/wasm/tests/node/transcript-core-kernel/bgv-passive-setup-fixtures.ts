import { deriveCanonicalObjectHash } from '#packages/crypto/src/index';

export const setupRequest = {
    ceremonyId: 'ceremony-main',
    manifestHash: deriveCanonicalObjectHash({
        objectType: 'ElectionManifestHash',
        manifest: 'passive-bgv-setup-test',
    }),
    rosterHash: deriveCanonicalObjectHash({
        objectType: 'RosterHash',
        roster: 'passive-bgv-setup-test',
    }),
    thresholdParametersHash: deriveCanonicalObjectHash({
        objectType: 'ThresholdParametersHash',
        threshold: 'passive-bgv-setup-test',
    }),
    participants: [
        {
            trusteeIdentity: 'trustee-1',
            rosterPosition: 0,
        },
        {
            trusteeIdentity: 'trustee-2',
            rosterPosition: 1,
        },
        {
            trusteeIdentity: 'trustee-3',
            rosterPosition: 2,
        },
    ],
    setupSeed: 'passive-bgv-setup-test-seed',
} as const;

export const validHash = (fill: string): string => fill.repeat(128);

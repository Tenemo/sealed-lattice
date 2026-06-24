import { expect } from 'vitest';

import { deriveProtocolHash } from '#packages/crypto/src/index';
import {
    TranscriptCoreKernelCommandError,
    type TranscriptCoreKernel,
} from '#packages/wasm/src/index';
import type { BgvPassiveSetupPackage } from '#packages/wasm/src/transcript-core-bridge/kernel-contracts';

export const setupRequest = {
    ceremonyId: 'ceremony-main',
    manifestHash: deriveProtocolHash('ElectionManifestHash', {
        manifest: 'passive-bgv-setup-test',
    }),
    rosterHash: deriveProtocolHash('RosterHash', {
        roster: 'passive-bgv-setup-test',
    }),
    thresholdParametersHash: deriveProtocolHash('ThresholdParametersHash', {
        threshold: 'passive-bgv-setup-test',
    }),
    participants: [
        {
            trusteeIdentity: 'trustee-1',
            rosterPosition: 0,
            boardPosition: 3,
        },
        {
            trusteeIdentity: 'trustee-2',
            rosterPosition: 1,
            boardPosition: 4,
        },
        {
            trusteeIdentity: 'trustee-3',
            rosterPosition: 2,
            boardPosition: 5,
        },
    ],
    setupSeed: 'passive-bgv-setup-test-seed',
} as const;

export const rebindSetupPackageHash = (
    kernel: TranscriptCoreKernel,
    setupPackage: BgvPassiveSetupPackage,
): BgvPassiveSetupPackage => {
    const hashInput = structuredClone(setupPackage) as Record<string, unknown>;
    delete hashInput.setupPackageHash;

    return {
        ...setupPackage,
        setupPackageHash: kernel.deriveProtocolHash({
            namespace: 'BGVPassiveSetupPackageHash',
            value: hashInput,
        }),
    };
};

type MutableJsonRecord = Record<string, unknown>;
type JsonPathSegment = string | number;

export const validHash = (fill: string): string => fill.repeat(128);

export const setPathValue = (
    target: unknown,
    path: readonly JsonPathSegment[],
    value: unknown,
): void => {
    let currentValue = target;
    for (const pathSegment of path.slice(0, -1)) {
        currentValue =
            typeof pathSegment === 'number'
                ? (currentValue as unknown[])[pathSegment]
                : (currentValue as MutableJsonRecord)[pathSegment];
    }
    const finalSegment = path[path.length - 1];
    if (finalSegment === undefined) {
        throw new Error('Cannot set an empty JSON path.');
    }
    if (typeof finalSegment === 'number') {
        (currentValue as unknown[])[finalSegment] = value;
    } else {
        (currentValue as MutableJsonRecord)[finalSegment] = value;
    }
};

export const arrayAtPath = (
    target: unknown,
    path: readonly JsonPathSegment[],
): unknown[] => {
    let currentValue = target;
    for (const pathSegment of path) {
        currentValue =
            typeof pathSegment === 'number'
                ? (currentValue as unknown[])[pathSegment]
                : (currentValue as MutableJsonRecord)[pathSegment];
    }

    return currentValue as unknown[];
};

export const expectReboundSetupPackageToBeRejected = (
    kernel: TranscriptCoreKernel,
    setupPackage: BgvPassiveSetupPackage,
): void => {
    expect(() =>
        kernel.verifyBgvPassiveSetup({
            setupPackage: rebindSetupPackageHash(kernel, setupPackage),
        }),
    ).toThrow(TranscriptCoreKernelCommandError);
};

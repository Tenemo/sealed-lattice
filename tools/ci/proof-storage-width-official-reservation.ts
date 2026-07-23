import { createHash } from 'node:crypto';
import { mkdir, open } from 'node:fs/promises';
import path from 'node:path';

import {
    proofStorageWidthProfile,
    proofStorageWidthSchedule,
    type ProofStorageWidth,
} from './proof-storage-width-evidence.js';

const sha256HexPattern = /^[0-9a-f]{64}$/u;
const commitHashPattern = /^[0-9a-f]{40}$/u;

export const defaultProofStorageWidthOfficialReservationRootPath = path.resolve(
    'logs',
    'proof-storage-width-official-reservations-v1',
);

const sha256Json = (value: unknown): string =>
    createHash('sha256').update(JSON.stringify(value)).digest('hex');

const requireSha256Hex = (value: string, fieldName: string): void => {
    if (!sha256HexPattern.test(value)) {
        throw new Error(
            `${fieldName} must be an exact lowercase SHA-256 digest.`,
        );
    }
};

const requireCommitHash = (value: string, fieldName: string): void => {
    if (!commitHashPattern.test(value)) {
        throw new Error(`${fieldName} must be an exact lowercase commit hash.`);
    }
};

export const buildProofStorageWidthNativeReservationIdentity = (input: {
    readonly memoryLimitBytes: number;
    readonly officialOwner: string;
    readonly sourceCommitHash: string;
}): Readonly<{
    identityRecord: Readonly<Record<string, unknown>>;
    identitySha256Hex: string;
}> => {
    requireCommitHash(
        input.sourceCommitHash,
        'Native reservation source commit',
    );
    if (
        !Number.isSafeInteger(input.memoryLimitBytes) ||
        input.memoryLimitBytes <= 0
    ) {
        throw new Error(
            'Native reservation memory limit must be a positive safe integer.',
        );
    }
    if (input.officialOwner.length === 0) {
        throw new Error('Native reservation official owner must be nonempty.');
    }
    const identityRecord = Object.freeze({
        absoluteCapTable: {
            identifier: proofStorageWidthProfile.absoluteCapTableIdentifier,
            maximumCommonProofByteLength:
                proofStorageWidthProfile.maximumCommonProofByteLength.toString(),
            maximumCopiedBufferByteLength:
                proofStorageWidthProfile.maximumCopiedBufferByteLength.toString(),
            maximumLocalRecordSealInvocationCount:
                proofStorageWidthProfile.maximumLocalRecordSealInvocationCount.toString(),
            maximumLocalRecordSealedPlaintextByteLength:
                proofStorageWidthProfile.maximumLocalRecordSealedPlaintextByteLength.toString(),
            maximumPhysicalObjectCount:
                proofStorageWidthProfile.maximumPhysicalObjectCount.toString(),
            maximumStoredScratchByteLength:
                proofStorageWidthProfile.maximumStoredScratchByteLength.toString(),
            maximumTransportByteLength:
                proofStorageWidthProfile.maximumTransportByteLength.toString(),
            maximumWasmMemoryByteLength:
                proofStorageWidthProfile.maximumWasmMemoryByteLength.toString(),
        },
        exactCandidate: {
            firstDataModulus: proofStorageWidthProfile.firstDataModulus,
            materialRadix: proofStorageWidthProfile.materialRadix,
            plaintextModulus: proofStorageWidthProfile.plaintextModulus,
            ringDimension: proofStorageWidthProfile.ringDimension,
            rosterSize: proofStorageWidthProfile.rosterSize,
        },
        formatVersion: 1,
        frozenInput: {
            derivationAlgorithm:
                proofStorageWidthProfile.publicColumnDerivationAlgorithm,
            derivationDomain: proofStorageWidthProfile.publicColumnInputDomain,
            derivationSeedHex: proofStorageWidthProfile.publicColumnSeedHex,
            frozenIdentityHashDomain:
                proofStorageWidthProfile.frozenInputIdentityHashDomain,
            frozenIdentityShake256Hex:
                proofStorageWidthProfile.frozenInputIdentityShake256Hex,
            recipeIdentifier:
                proofStorageWidthProfile.frozenInputRecipeIdentifier,
            widthIdentityHashDomain:
                proofStorageWidthProfile.widthInputIdentityHashDomain,
        },
        guard: {
            aggregateProcessTree: true,
            memoryLimitBytes: input.memoryLimitBytes,
            resourceSampleIntervalMilliseconds: 100,
        },
        officialOwner: input.officialOwner,
        profiles: {
            backend: proofStorageWidthProfile.backendProfileIdentifier,
            custody: {
                identifier: proofStorageWidthProfile.custodySchemaIdentifier,
                maximumNativePathByteLength:
                    proofStorageWidthProfile.maximumNativeCustodyPathByteLength,
                version: proofStorageWidthProfile.custodySchemaVersion,
            },
            intendedReleaseRuntime:
                proofStorageWidthProfile.intendedReleaseRuntime,
            measurementRuntime: proofStorageWidthProfile.measurementRuntime,
            release: proofStorageWidthProfile.releaseProfileIdentifier,
        },
        sourceCommitHash: input.sourceCommitHash,
        widthSchedule: proofStorageWidthSchedule,
    });
    return Object.freeze({
        identityRecord,
        identitySha256Hex: sha256Json(identityRecord),
    });
};

export const buildProofStorageWidthBrowserReservationIdentity = (input: {
    readonly nativeAggregateSha256Hex: string;
    readonly nativeReservationIdentitySha256Hex: string;
    readonly officialOwner: string;
    readonly rawWasmSha256Hex: string;
    readonly sourceCommitHash: string;
}): Readonly<{
    identityRecord: Readonly<Record<string, unknown>>;
    identitySha256Hex: string;
}> => {
    requireCommitHash(
        input.sourceCommitHash,
        'Browser reservation source commit',
    );
    requireSha256Hex(
        input.nativeAggregateSha256Hex,
        'Browser reservation native aggregate',
    );
    requireSha256Hex(
        input.nativeReservationIdentitySha256Hex,
        'Browser reservation native identity',
    );
    requireSha256Hex(input.rawWasmSha256Hex, 'Browser reservation raw WASM');
    if (input.officialOwner.length === 0) {
        throw new Error('Browser reservation official owner must be nonempty.');
    }
    const identityRecord = Object.freeze({
        formatVersion: 1,
        nativeAggregateSha256Hex: input.nativeAggregateSha256Hex,
        nativeReservationIdentitySha256Hex:
            input.nativeReservationIdentitySha256Hex,
        officialOwner: input.officialOwner,
        rawWasmSha256Hex: input.rawWasmSha256Hex,
        representativeWidth:
            proofStorageWidthProfile.representativeBrowserWidth,
        sourceCommitHash: input.sourceCommitHash,
    });
    return Object.freeze({
        identityRecord,
        identitySha256Hex: sha256Json(identityRecord),
    });
};

const requireReservationRootOutsideRun = (input: {
    readonly reservationRootPath: string;
    readonly runDirectoryPath: string;
}): string => {
    if (!path.isAbsolute(input.reservationRootPath)) {
        throw new Error('The official reservation root path must be absolute.');
    }
    const reservationRootPath = path.resolve(input.reservationRootPath);
    const runDirectoryPath = path.resolve(input.runDirectoryPath);
    const relativeFromRun = path.relative(
        runDirectoryPath,
        reservationRootPath,
    );
    if (
        relativeFromRun.length === 0 ||
        (!relativeFromRun.startsWith(`..${path.sep}`) &&
            relativeFromRun !== '..' &&
            !path.isAbsolute(relativeFromRun))
    ) {
        throw new Error(
            'The durable official reservation root must stay outside the per-run directory.',
        );
    }
    return reservationRootPath;
};

const writeReservationRecord = async (input: {
    readonly filePath: string;
    readonly record: Readonly<Record<string, unknown>>;
}): Promise<void> => {
    const fileHandle = await open(input.filePath, 'wx');
    try {
        await fileHandle.writeFile(`${JSON.stringify(input.record)}\n`, 'utf8');
        await fileHandle.sync();
    } finally {
        await fileHandle.close();
    }
};

const appendExistingReservationRecord = async (input: {
    readonly filePath: string;
    readonly record: Readonly<Record<string, unknown>>;
}): Promise<void> => {
    const fileHandle = await open(input.filePath, 'r+');
    try {
        const fileStatistics = await fileHandle.stat();
        const serializedRecord = `${JSON.stringify(input.record)}\n`;
        const { bytesWritten } = await fileHandle.write(
            serializedRecord,
            fileStatistics.size,
            'utf8',
        );
        if (bytesWritten !== Buffer.byteLength(serializedRecord, 'utf8')) {
            throw new Error(
                'The durable official reservation outcome was only partially appended.',
            );
        }
        await fileHandle.sync();
    } finally {
        await fileHandle.close();
    }
};

export const createProofStorageWidthNativeSampleReservation = async (input: {
    readonly identitySha256Hex: string;
    readonly manifestIdentityShake256Hex: string;
    readonly officialOwner: string;
    readonly reservationRootPath?: string;
    readonly runDirectoryPath: string;
    readonly scheduleOrdinal: number;
    readonly sourceCommitHash: string;
    readonly width: ProofStorageWidth;
}): Promise<string> => {
    requireSha256Hex(input.identitySha256Hex, 'Native reservation identity');
    requireCommitHash(
        input.sourceCommitHash,
        'Native reservation source commit',
    );
    if (!/^[0-9a-f]{128}$/u.test(input.manifestIdentityShake256Hex)) {
        throw new Error(
            'Native reservation manifest identity must be lowercase SHAKE256-512.',
        );
    }
    if (input.officialOwner.length === 0) {
        throw new Error('Native reservation official owner must be nonempty.');
    }
    if (
        !Number.isSafeInteger(input.scheduleOrdinal) ||
        input.scheduleOrdinal < 1 ||
        proofStorageWidthSchedule[input.scheduleOrdinal - 1] !== input.width
    ) {
        throw new Error(
            'Native reservation ordinal and width must match the exact schedule.',
        );
    }
    const reservationRootPath = requireReservationRootOutsideRun({
        reservationRootPath:
            input.reservationRootPath ??
            defaultProofStorageWidthOfficialReservationRootPath,
        runDirectoryPath: input.runDirectoryPath,
    });
    const reservationDirectoryPath = path.join(
        reservationRootPath,
        'native',
        input.identitySha256Hex,
    );
    await mkdir(reservationDirectoryPath, { recursive: true });
    const reservationPath = path.join(
        reservationDirectoryPath,
        `width-${input.scheduleOrdinal}-started.json`,
    );
    try {
        await writeReservationRecord({
            filePath: reservationPath,
            record: {
                eventType: 'official-native-width-sample-started',
                identitySha256Hex: input.identitySha256Hex,
                manifestIdentityShake256Hex: input.manifestIdentityShake256Hex,
                officialOwner: input.officialOwner,
                recordedAtUnixMilliseconds: Date.now(),
                scheduleOrdinal: input.scheduleOrdinal,
                sourceCommitHash: input.sourceCommitHash,
                width: input.width,
            },
        });
    } catch (error) {
        if (
            typeof error === 'object' &&
            error !== null &&
            'code' in error &&
            error.code === 'EEXIST'
        ) {
            throw Object.assign(
                new Error(
                    `Official native width ${input.width} already has a durable started reservation; no replacement sample is permitted.`,
                ),
                { cause: error },
            );
        }
        throw error;
    }
    return reservationPath;
};

export const createProofStorageWidthBrowserSampleReservation = async (input: {
    readonly identitySha256Hex: string;
    readonly nativeAggregateSha256Hex: string;
    readonly officialOwner: string;
    readonly rawWasmSha256Hex: string;
    readonly reservationRootPath?: string;
    readonly runDirectoryPath: string;
    readonly sourceCommitHash: string;
}): Promise<string> => {
    requireSha256Hex(input.identitySha256Hex, 'Browser reservation identity');
    requireSha256Hex(
        input.nativeAggregateSha256Hex,
        'Browser reservation native aggregate',
    );
    requireSha256Hex(input.rawWasmSha256Hex, 'Browser reservation raw WASM');
    requireCommitHash(
        input.sourceCommitHash,
        'Browser reservation source commit',
    );
    if (input.officialOwner.length === 0) {
        throw new Error('Browser reservation official owner must be nonempty.');
    }
    const reservationRootPath = requireReservationRootOutsideRun({
        reservationRootPath:
            input.reservationRootPath ??
            defaultProofStorageWidthOfficialReservationRootPath,
        runDirectoryPath: input.runDirectoryPath,
    });
    const reservationDirectoryPath = path.join(
        reservationRootPath,
        'browser',
        input.identitySha256Hex,
    );
    await mkdir(reservationDirectoryPath, { recursive: true });
    const reservationPath = path.join(
        reservationDirectoryPath,
        'browser-started.json',
    );
    try {
        await writeReservationRecord({
            filePath: reservationPath,
            record: {
                eventType: 'official-browser-width-sample-started',
                identitySha256Hex: input.identitySha256Hex,
                nativeAggregateSha256Hex: input.nativeAggregateSha256Hex,
                officialOwner: input.officialOwner,
                rawWasmSha256Hex: input.rawWasmSha256Hex,
                recordedAtUnixMilliseconds: Date.now(),
                sourceCommitHash: input.sourceCommitHash,
                width: proofStorageWidthProfile.representativeBrowserWidth,
            },
        });
    } catch (error) {
        if (
            typeof error === 'object' &&
            error !== null &&
            'code' in error &&
            error.code === 'EEXIST'
        ) {
            throw Object.assign(
                new Error(
                    'Official browser width evidence already has a durable started reservation; no replacement sample is permitted.',
                ),
                { cause: error },
            );
        }
        throw error;
    }
    return reservationPath;
};

export const appendProofStorageWidthOfficialReservationOutcome = async (input: {
    readonly failureName?: string;
    readonly outcome: 'failed' | 'validated';
    readonly reservationPath: string;
}): Promise<void> => {
    if (!path.isAbsolute(input.reservationPath)) {
        throw new Error(
            'The official reservation outcome path must be absolute.',
        );
    }
    await appendExistingReservationRecord({
        filePath: input.reservationPath,
        record: {
            ...(input.failureName === undefined
                ? {}
                : { failureName: input.failureName }),
            eventType: 'official-sample-outcome',
            outcome: input.outcome,
            recordedAtUnixMilliseconds: Date.now(),
        },
    });
};

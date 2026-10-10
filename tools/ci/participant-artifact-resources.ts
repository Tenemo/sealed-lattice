import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { participantRuntimeIdentity } from '#tools/ci/build-participant-module.js';

const root = fileURLToPath(new URL('../../', import.meta.url));
const digest = (bytes: Uint8Array) =>
    createHash('sha512').update(bytes).digest('hex');

// Reads only the shared SDK build. It neither builds nor substitutes source
// estimates for absent artifacts. The injectable reader keeps refusal tests
// independent of the caller's current build and never executes bundled code.
export const readParticipantArtifactResources = (
    read: (file: string) => Buffer = (file) =>
        readFileSync(path.join(root, file)),
) => {
    const load = (file: string) => {
        try {
            return read(file);
        } catch (cause) {
            throw Object.assign(
                new Error(
                    `Missing SDK resource artifact or source ${file}; run the shared SDK build before the census.`,
                ),
                { cause },
            );
        }
    };
    const prefix = 'packages/sdk/dist/';
    const sourceManifest = load(prefix + 'participant-source-manifest.json');
    const parsed: unknown = JSON.parse(sourceManifest.toString('utf8'));
    if (
        typeof parsed !== 'object' ||
        parsed === null ||
        !('files' in parsed) ||
        !Array.isArray(parsed.files) ||
        parsed.files.length === 0
    )
        throw new Error('Malformed SDK source manifest.');
    for (const item of parsed.files as unknown[]) {
        if (
            typeof item !== 'object' ||
            item === null ||
            !('file' in item) ||
            !('sha512' in item) ||
            !('bytes' in item) ||
            typeof item.file !== 'string' ||
            typeof item.sha512 !== 'string' ||
            !/^[0-9a-f]{128}$/u.test(item.sha512) ||
            typeof item.bytes !== 'number' ||
            !Number.isSafeInteger(item.bytes) ||
            item.bytes < 0
        )
            throw new Error('Malformed SDK source manifest entry.');
        const resolved = path.resolve(root, item.file);
        const relative = path.relative(root, resolved);
        if (
            relative.startsWith('..') ||
            path.isAbsolute(relative) ||
            item.file.includes('\\')
        )
            throw new Error(
                'SDK source manifest path is outside its source grammar.',
            );
        const source = load(item.file);
        if (source.length !== item.bytes || digest(source) !== item.sha512)
            throw new Error(
                `Stale SDK build source ${item.file}; rebuild before regenerating the resource census.`,
            );
    }
    const module = load(prefix + 'participant.wasm'),
        worker = load(prefix + 'participant-worker.js'),
        sdk = load(prefix + 'index.js');
    if (
        module.length === 0 ||
        module.length > 8_388_608 ||
        worker.length === 0 ||
        sdk.length === 0
    )
        throw new Error('Unsupported SDK artifact length.');
    const identity = participantRuntimeIdentity(sourceManifest, module, worker);
    const entry = sdk.toString('utf8');
    if (
        ![identity.source, identity.module, identity.worker].every((value) =>
            entry.includes(value),
        )
    )
        throw new Error(
            'SDK entry and runtime artifacts belong to different builds.',
        );
    return {
        identity,
        sdkDigest: digest(sdk),
        moduleBytes: BigInt(module.length),
        workerBytes: BigInt(worker.length),
        sdkBytes: BigInt(sdk.length),
    };
};

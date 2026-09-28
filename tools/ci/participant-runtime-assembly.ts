import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';

import {
    buildParticipantModule,
    participantRuntimeIdentity,
} from '#tools/ci/build-participant-module.js';
import type { ActiveLocalRunLog } from '#tools/ci/local-run-log.js';

const root = path.resolve('.');
const packageOutput = path.join(root, 'packages/sdk/dist');

export type ParticipantRuntime = Readonly<{
    // The SDK entry that serves the participant API to the page, and the
    // foundation kernel it ships beside it for archive records.
    sdk: Buffer;
    kernel: Buffer;
    module: Buffer;
    worker: Buffer;
    identity: Readonly<{
        runtime: string;
        source: string;
        module: string;
        worker: string;
    }>;
}>;

const sha512 = (bytes: Uint8Array | string) =>
    createHash('sha512').update(bytes).digest('hex');

// A corrupt participant's client claims the honest runtime: its worker
// fetches and hashes the honest module as the honest worker does, then
// compiles the module at the client's own path, which signs authentic invalid
// ballots. Its page checks the patched worker's digest instead.
export type CorruptParticipantClient = Readonly<{
    feature: string;
    path: string;
    module: Buffer;
    worker: Buffer;
    moduleDigest: string;
    workerDigest: string;
}>;

// Takes the SDK entry, participant module, worker and source manifest the SDK
// build packaged, copies every listed source into the run directory after
// checking its digest, keeps the runtime it serves among the run's artifacts,
// and computes the runtime identity the worker recomputes. When requested, it
// also builds the invalid-ballot client from the same sources.
export const assembleParticipantRuntime = async (
    runLog: ActiveLocalRunLog,
    invalidBallot: boolean,
): Promise<
    Readonly<{
        runtime: ParticipantRuntime;
        invalidBallotClient: CorruptParticipantClient | undefined;
    }>
> => {
    const [sdk, kernel, module, worker, sourceManifest] = await Promise.all(
        [
            'index.js',
            'sealed-lattice-kernel.wasm',
            'participant.wasm',
            'participant-worker.js',
            'participant-source-manifest.json',
        ].map((name) => readFile(path.join(packageOutput, name))),
    );
    const listed = (
        JSON.parse(sourceManifest.toString('utf8')) as {
            files: { file: string; sha512: string; bytes: number }[];
        }
    ).files;
    for (const { file, sha512: digest } of listed) {
        const bytes = await readFile(path.join(root, file));
        assert.equal(
            sha512(bytes),
            digest,
            'The packaged participant runtime was built from other sources: ' +
                file,
        );
        const destination = path.join(runLog.runDirectoryPath, 'sources', file);
        await mkdir(path.dirname(destination), { recursive: true });
        await writeFile(destination, bytes, { flag: 'wx' });
    }
    await writeFile(
        path.join(runLog.runDirectoryPath, 'source-manifest.json'),
        sourceManifest,
        { flag: 'wx' },
    );
    const identity = participantRuntimeIdentity(sourceManifest, module, worker);
    const invalidBallotModule = invalidBallot
        ? (await buildParticipantModule('invalid-ballot')).module
        : undefined;
    const invalidBallotClient =
        invalidBallotModule === undefined
            ? undefined
            : (() => {
                  const clientPath = 'invalid-ballot-participant.wasm';
                  const honestCompile =
                      'await WebAssembly.compile(new Uint8Array(moduleBytes))';
                  const bundled = worker.toString('utf8');
                  assert.equal(
                      bundled.split(honestCompile).length,
                      2,
                      'The worker bundle does not compile its module once.',
                  );
                  // The replacement names only globals, so it holds whatever
                  // names the bundler chose.
                  const patched = Buffer.from(
                      bundled.replace(
                          honestCompile,
                          'await WebAssembly.compile(await (await fetch(location.origin + "/' +
                              clientPath +
                              '")).arrayBuffer())',
                      ),
                  );
                  const client = {
                      feature: 'invalid-ballot',
                      path: clientPath,
                      module: invalidBallotModule,
                      worker: patched,
                      moduleDigest: sha512(invalidBallotModule),
                      workerDigest: sha512(patched),
                  };
                  assert.notEqual(
                      client.moduleDigest,
                      identity.module,
                      'The invalid-ballot module equals the honest module.',
                  );
                  return client;
              })();
    await mkdir(runLog.artifactDirectoryPath, { recursive: true });
    for (const [name, bytes] of [
        ['index.js', sdk],
        ['sealed-lattice-kernel.wasm', kernel],
        ['participant.wasm', module],
        ['worker.js', worker],
        ...(invalidBallotClient === undefined
            ? []
            : ([
                  [invalidBallotClient.path, invalidBallotClient.module],
                  ['invalid-ballot-worker.js', invalidBallotClient.worker],
              ] as const)),
    ] as const)
        await writeFile(path.join(runLog.artifactDirectoryPath, name), bytes, {
            flag: 'wx',
        });
    return {
        runtime: { sdk, kernel, module, worker, identity },
        invalidBallotClient,
    };
};

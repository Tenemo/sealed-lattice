import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';

import { buildParticipantModule } from '#tools/ci/build-participant-module.js';
import type { ActiveLocalRunLog } from '#tools/ci/local-run-log.js';

const root = path.resolve('.');
const packageOutput = path.join(root, 'packages/sdk/dist');

export type ParticipantRuntime = Readonly<{
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

// Takes the participant module, worker and source manifest the SDK build
// packaged, copies every listed source into the run directory after checking
// its digest, and computes the runtime identity the worker recomputes. When
// requested, it also builds the invalid-ballot client from the same sources.
export const assembleParticipantRuntime = async (
    runLog: ActiveLocalRunLog,
    invalidBallot: boolean,
): Promise<
    Readonly<{
        runtime: ParticipantRuntime;
        invalidBallotClient: CorruptParticipantClient | undefined;
    }>
> => {
    const [module, worker, sourceManifest] = await Promise.all(
        [
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
    const identity = {
        source: sha512(sourceManifest),
        module: sha512(module),
        worker: sha512(worker),
    };
    const runtime = createHash('sha512')
        .update('participant-runtime/8')
        .update(Buffer.from(identity.source, 'hex'))
        .update(Buffer.from(identity.module, 'hex'))
        .update(Buffer.from(identity.worker, 'hex'))
        .digest('hex');
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
    for (const [name, bytes] of [
        ['participant.wasm', module],
        ['worker.js', worker],
        ...(invalidBallotClient === undefined
            ? []
            : ([
                  [invalidBallotClient.path, invalidBallotClient.module],
                  ['invalid-ballot-worker.js', invalidBallotClient.worker],
              ] as const)),
    ] as const)
        await writeFile(path.join(runLog.runDirectoryPath, name), bytes, {
            flag: 'wx',
        });
    return {
        runtime: {
            module,
            worker,
            identity: { runtime, ...identity },
        },
        invalidBallotClient,
    };
};

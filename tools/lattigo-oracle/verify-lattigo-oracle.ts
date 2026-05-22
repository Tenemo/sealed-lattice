import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFile, stat } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const repoRoot = fileURLToPath(new URL('../../', import.meta.url));
const pinnedReferencePath = path.join(
    repoRoot,
    'reference-projects/lattigo/pinned-reference.json',
);
const oracleDirectoryPath = path.join(repoRoot, 'tools/lattigo-oracle');

type PinnedReference = {
    readonly archivePath: string;
    readonly archiveSha256: string;
    readonly containerBaseImage: string;
    readonly containerBaseImageDigest: string;
    readonly localCheckoutPath: string;
    readonly oracleCommandDigest: string;
    readonly oracleDockerfileDigest: string;
    readonly pinnedCommit: string;
    readonly runtimeUse: string;
    readonly protocolEvidenceUse: string;
};

const sha256File = async (filePath: string): Promise<string> => {
    const bytes = await readFile(filePath);

    return createHash('sha256').update(bytes).digest('hex');
};

const sha256Text = (text: string): string =>
    createHash('sha256').update(text).digest('hex');

export const loadPinnedReference = async (): Promise<PinnedReference> =>
    JSON.parse(await readFile(pinnedReferencePath, 'utf8')) as PinnedReference;

const assertPinnedDigest = (
    label: string,
    actualDigest: string,
    expectedDigest: string,
): void => {
    if (actualDigest !== expectedDigest) {
        throw new Error(
            `The pinned Lattigo ${label} digest changed: ${actualDigest}.`,
        );
    }
};

export const verifyPinnedReference = async (): Promise<{
    readonly archivePresent: boolean;
    readonly checkoutPresent: boolean;
    readonly commandDigest: string;
    readonly dockerfileDigest: string;
}> => {
    const pinnedReference = await loadPinnedReference();
    if (pinnedReference.runtimeUse !== 'forbidden') {
        throw new Error(
            'The Lattigo reference must stay forbidden at runtime.',
        );
    }
    if (pinnedReference.protocolEvidenceUse !== 'forbidden') {
        throw new Error(
            'The Lattigo reference must stay forbidden as protocol evidence.',
        );
    }

    const archiveAbsolutePath = path.join(
        repoRoot,
        pinnedReference.archivePath,
    );
    const checkoutAbsolutePath = path.join(
        repoRoot,
        pinnedReference.localCheckoutPath,
    );
    let archivePresent = false;
    try {
        const archiveDigest = await sha256File(archiveAbsolutePath);
        archivePresent = true;
        if (archiveDigest !== pinnedReference.archiveSha256) {
            throw new Error(
                `The pinned Lattigo archive digest changed: ${archiveDigest}.`,
            );
        }
    } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
            throw error;
        }
    }

    let checkoutPresent = false;
    try {
        checkoutPresent = (await stat(checkoutAbsolutePath)).isDirectory();
    } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
            throw error;
        }
    }

    const [mainSource, goModule, dockerfile] = await Promise.all([
        readFile(path.join(oracleDirectoryPath, 'main.go'), 'utf8'),
        readFile(path.join(oracleDirectoryPath, 'go.mod'), 'utf8'),
        readFile(path.join(oracleDirectoryPath, 'Dockerfile'), 'utf8'),
    ]);

    const expectedBaseImageReference = `${pinnedReference.containerBaseImage}@${pinnedReference.containerBaseImageDigest}`;
    const dockerfileFirstLine = dockerfile.split(/\r?\n/u)[0];
    if (dockerfileFirstLine !== `FROM ${expectedBaseImageReference}`) {
        throw new Error(
            `The Lattigo oracle Dockerfile must pin ${expectedBaseImageReference}.`,
        );
    }
    const commandDigest = sha256Text(`${mainSource}\n${goModule}`);
    const dockerfileDigest = sha256Text(dockerfile);
    assertPinnedDigest(
        'oracle command',
        commandDigest,
        pinnedReference.oracleCommandDigest,
    );
    assertPinnedDigest(
        'oracle Dockerfile',
        dockerfileDigest,
        pinnedReference.oracleDockerfileDigest,
    );

    return {
        archivePresent,
        checkoutPresent,
        commandDigest,
        dockerfileDigest,
    };
};

const runDockerOracle = async (): Promise<void> => {
    await new Promise<void>((resolve, reject) => {
        const imageName = 'sealed-lattice-lattigo-oracle:m7';
        const build = spawn(
            'docker',
            [
                'build',
                '-f',
                'tools/lattigo-oracle/Dockerfile',
                '-t',
                imageName,
                '.',
            ],
            {
                cwd: repoRoot,
                stdio: 'inherit',
            },
        );
        build.once('error', reject);
        build.once('exit', (code) => {
            if (code === 0) {
                resolve();
            } else {
                reject(
                    new Error(`Docker oracle build exited with code ${code}.`),
                );
            }
        });
    });

    await new Promise<void>((resolve, reject) => {
        const run = spawn(
            'docker',
            ['run', '--rm', 'sealed-lattice-lattigo-oracle:m7'],
            {
                cwd: repoRoot,
                stdio: 'inherit',
            },
        );
        run.once('error', reject);
        run.once('exit', (code) => {
            if (code === 0) {
                resolve();
            } else {
                reject(
                    new Error(`Docker oracle run exited with code ${code}.`),
                );
            }
        });
    });
};

const main = async (): Promise<void> => {
    const report = await verifyPinnedReference();
    console.log(
        JSON.stringify(
            {
                ok: true,
                ...report,
                dockerOracleRun:
                    process.env.SEALED_LATTICE_RUN_LATTIGO_DOCKER_ORACLE ===
                    '1',
            },
            null,
            2,
        ),
    );

    if (process.env.SEALED_LATTICE_RUN_LATTIGO_DOCKER_ORACLE === '1') {
        await runDockerOracle();
    }
};

const scriptEntryPoint = process.argv[1];
const isMainModule =
    scriptEntryPoint !== undefined &&
    import.meta.url === pathToFileURL(scriptEntryPoint).href;

if (isMainModule) {
    void main();
}

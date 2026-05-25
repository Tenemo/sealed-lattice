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
const oracleCommandInputRelativePaths = [
    'main.go',
    'go.mod',
    'go.sum',
    'internal/extract-pinned-archive/main.go',
] as const;

type PinnedReference = {
    readonly allowedUse: string;
    readonly archivePath: string;
    readonly archiveSha256: string;
    readonly claimBoundary: string;
    readonly containerBaseImage: string;
    readonly containerBaseImageDigest: string;
    readonly goToolchain: string;
    readonly localCheckoutPath: string;
    readonly oracleCommandDigest: string;
    readonly oracleDockerfileDigest: string;
    readonly pinnedCommit: string;
    readonly pinnedCommitDate: string;
    readonly pinnedCommitUrl: string;
    readonly referenceName: string;
    readonly repository: string;
    readonly runtimeUse: string;
    readonly protocolEvidenceUse: string;
    readonly schemaVersion: number;
};

const sha256File = async (filePath: string): Promise<string> => {
    const bytes = await readFile(filePath);

    return createHash('sha256').update(bytes).digest('hex');
};

const sha256Text = (text: string): string =>
    createHash('sha256').update(text).digest('hex');

const sha256OracleCommandInputs = (
    commandInputs: readonly {
        readonly relativePath: string;
        readonly source: string;
    }[],
): string =>
    sha256Text(
        commandInputs
            .map(({ relativePath, source }) => `${relativePath}\n${source}`)
            .join('\n'),
    );

export const loadPinnedReference = async (): Promise<PinnedReference> =>
    JSON.parse(await readFile(pinnedReferencePath, 'utf8')) as PinnedReference;

export const assertPinnedDigest = (
    label: string,
    actualDigest: string,
    expectedDigest: string,
): void => {
    if (actualDigest !== expectedDigest) {
        throw new Error(
            `The pinned Lattigo ${label} digest changed: actual ${actualDigest}, expected ${expectedDigest}. Review the oracle change before updating reference-projects/lattigo/pinned-reference.json.`,
        );
    }
};

const goVersionFromPinnedToolchain = (goToolchain: string): string => {
    const match = /^go(?<version>\d+\.\d+\.\d+)$/u.exec(goToolchain);
    if (match?.groups?.version === undefined) {
        throw new Error(
            `The pinned Lattigo Go toolchain is malformed: ${goToolchain}.`,
        );
    }

    return match.groups.version;
};

export const verifyPinnedReferenceMetadata = (
    pinnedReference: PinnedReference,
    goModule: string,
    dockerfile: string,
): void => {
    if (pinnedReference.schemaVersion !== 1) {
        throw new Error(
            `Unsupported Lattigo pinned-reference schema version: ${pinnedReference.schemaVersion}. Expected 1.`,
        );
    }
    if (pinnedReference.referenceName !== 'Lattigo') {
        throw new Error('The pinned reference must describe Lattigo.');
    }
    if (
        !pinnedReference.pinnedCommitUrl.endsWith(pinnedReference.pinnedCommit)
    ) {
        throw new Error(
            'The pinned Lattigo commit URL must end with the pinned commit.',
        );
    }
    if (!pinnedReference.archivePath.includes(pinnedReference.pinnedCommit)) {
        throw new Error(
            'The pinned Lattigo archive path must include the pinned commit.',
        );
    }
    if (
        !pinnedReference.localCheckoutPath.includes(
            pinnedReference.pinnedCommit,
        )
    ) {
        throw new Error(
            'The pinned Lattigo checkout path must include the pinned commit.',
        );
    }

    const pinnedGoVersion = goVersionFromPinnedToolchain(
        pinnedReference.goToolchain,
    );
    const goModuleVersion = /^go\s+(?<version>\d+\.\d+\.\d+)$/mu.exec(goModule)
        ?.groups?.version;
    if (goModuleVersion !== pinnedGoVersion) {
        throw new Error(
            `The Lattigo oracle go.mod Go version is ${goModuleVersion ?? 'missing'}, expected ${pinnedGoVersion} from pinned-reference.json.`,
        );
    }
    if (
        !pinnedReference.containerBaseImage.startsWith(
            `golang:${pinnedGoVersion}-`,
        )
    ) {
        throw new Error(
            `The Lattigo oracle container base image ${pinnedReference.containerBaseImage} must use Go ${pinnedGoVersion}.`,
        );
    }

    const expectedBaseImageReference = `${pinnedReference.containerBaseImage}@${pinnedReference.containerBaseImageDigest}`;
    const dockerfileFirstLine = dockerfile.split(/\r?\n/u)[0];
    if (dockerfileFirstLine !== `FROM ${expectedBaseImageReference}`) {
        throw new Error(
            `The Lattigo oracle Dockerfile must pin ${expectedBaseImageReference}.`,
        );
    }
    const expectedArchiveCopyLine = `COPY ${pinnedReference.archivePath} /workspace/${pinnedReference.archivePath}`;
    if (!dockerfile.includes(expectedArchiveCopyLine)) {
        throw new Error(
            'The Lattigo oracle Dockerfile must build from the pinned archive path.',
        );
    }
    if (!dockerfile.includes(pinnedReference.archiveSha256)) {
        throw new Error(
            'The Lattigo oracle Dockerfile must verify the pinned archive SHA-256 digest.',
        );
    }
    if (dockerfile.includes(`COPY ${pinnedReference.localCheckoutPath}`)) {
        throw new Error(
            'The Lattigo oracle Dockerfile must not copy the mutable local checkout as the build input.',
        );
    }
    if (
        !dockerfile.includes('go mod download') ||
        !dockerfile.includes('go mod verify') ||
        !dockerfile.includes('-mod=readonly')
    ) {
        throw new Error(
            'The Lattigo oracle Dockerfile must use pinned module resolution with go.sum verification.',
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
        assertPinnedDigest(
            'archive',
            archiveDigest,
            pinnedReference.archiveSha256,
        );
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

    const [dockerfile, commandInputs] = await Promise.all([
        readFile(path.join(oracleDirectoryPath, 'Dockerfile'), 'utf8'),
        Promise.all(
            oracleCommandInputRelativePaths.map(async (relativePath) => ({
                relativePath,
                source: await readFile(
                    path.join(oracleDirectoryPath, relativePath),
                    'utf8',
                ),
            })),
        ),
    ]);
    const goModule = commandInputs.find(
        ({ relativePath }) => relativePath === 'go.mod',
    )?.source;
    if (goModule === undefined) {
        throw new Error('The Lattigo oracle go.mod command input is missing.');
    }

    verifyPinnedReferenceMetadata(pinnedReference, goModule, dockerfile);
    const commandDigest = sha256OracleCommandInputs(commandInputs);
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

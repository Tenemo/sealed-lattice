// Requires Docker. Verifies the pinned Lattigo reference metadata, archive,
// Dockerfile, and oracle command Hashes, then builds and runs the pinned
// development-only Docker oracle against the committed canonical RNS fixtures.
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFile, stat } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { deriveProtocolHash } from '#packages/crypto/src/index';
import { isDirectlyInvokedModule } from '#tools/internal/entry-point.js';

const repoRoot = fileURLToPath(new URL('../../', import.meta.url));
const pinnedReferencePath = path.join(
    repoRoot,
    'tools/lattigo-oracle/pinned-reference.json',
);
const oracleDirectoryPath = path.join(repoRoot, 'tools/lattigo-oracle');
const oracleCommandInputRelativePaths = [
    'main.go',
    'go.mod',
    'go.sum',
    'sealed-lattice-canonical-rns-fixtures.json',
    'internal/extract-pinned-archive/main.go',
] as const;

type PinnedReference = {
    readonly allowedUse: string;
    readonly archivePath: string;
    readonly archiveSha256: string;
    readonly claimBoundary: string;
    readonly containerBaseImage: string;
    readonly containerBaseImageHash: string;
    readonly goToolchain: string;
    readonly localCheckoutPath: string;
    readonly oracleCommandHash: string;
    readonly oracleDockerfileHash: string;
    readonly pinnedCommit: string;
    readonly pinnedCommitDate: string;
    readonly pinnedCommitUrl: string;
    readonly referenceName: string;
    readonly repository: string;
    readonly runtimeUse: string;
    readonly protocolEvidenceUse: string;
    readonly schemaVersion: number;
};

export type ReferenceOracleHashBindings = {
    readonly referenceOracleCommitHash: string;
    readonly referenceOracleContainerHash: string;
    readonly referenceOracleCommandHash: string;
    readonly referenceOracleVectorRoot: string;
    readonly referenceOracleProfileHash: string;
    readonly records: {
        readonly commitRecord: unknown;
        readonly containerRecord: unknown;
        readonly commandRecord: unknown;
        readonly vectorRecord: unknown;
        readonly profileRecord: unknown;
    };
};

const sha256File = async (filePath: string): Promise<string> => {
    const bytes = await readFile(filePath);

    return createHash('sha256').update(bytes).digest('hex');
};

const sha256Text = (text: string): string =>
    createHash('sha256').update(text).digest('hex');

const escapeRegExp = (value: string): string =>
    value.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');

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

export const assertPinnedHash = (
    label: string,
    actualHash: string,
    expectedHash: string,
): void => {
    if (actualHash !== expectedHash) {
        throw new Error(
            `The pinned Lattigo ${label} hash changed: actual ${actualHash}, expected ${expectedHash}. Review the oracle change before updating tools/lattigo-oracle/pinned-reference.json.`,
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

    const expectedBaseImageReference = `${pinnedReference.containerBaseImage}@${pinnedReference.containerBaseImageHash}`;
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
    const archiveChecksumCommandPattern = new RegExp(
        [
            String.raw`(?:^|\n)\s*RUN\s+echo\s+["']`,
            escapeRegExp(pinnedReference.archiveSha256),
            String.raw`\s+/workspace/`,
            escapeRegExp(pinnedReference.archivePath),
            String.raw`["']\s*\|\s*sha256sum\s+-c\s+-`,
        ].join(''),
        'u',
    );
    if (!archiveChecksumCommandPattern.test(dockerfile)) {
        throw new Error(
            'The Lattigo oracle Dockerfile must verify the pinned archive SHA-256 hash with sha256sum -c against the pinned archive path.',
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

export const buildReferenceOracleHashBindings = (
    pinnedReference: PinnedReference,
    commandHash: string,
    dockerfileHash: string,
): ReferenceOracleHashBindings => {
    const commitRecord = {
        referenceName: pinnedReference.referenceName,
        repository: pinnedReference.repository,
        pinnedCommit: pinnedReference.pinnedCommit,
        pinnedCommitDate: pinnedReference.pinnedCommitDate,
        pinnedCommitUrl: pinnedReference.pinnedCommitUrl,
        runtimeUse: pinnedReference.runtimeUse,
        protocolEvidenceUse: pinnedReference.protocolEvidenceUse,
    };
    const containerRecord = {
        referenceName: pinnedReference.referenceName,
        containerBaseImage: pinnedReference.containerBaseImage,
        containerBaseImageHash: pinnedReference.containerBaseImageHash,
        goToolchain: pinnedReference.goToolchain,
        oracleDockerfileHash: dockerfileHash,
        protocolEvidenceUse: pinnedReference.protocolEvidenceUse,
    };
    const commandRecord = {
        referenceName: pinnedReference.referenceName,
        oracleCommandHash: commandHash,
        commandInputRelativePaths: oracleCommandInputRelativePaths,
        runtimeUse: pinnedReference.runtimeUse,
        protocolEvidenceUse: pinnedReference.protocolEvidenceUse,
    };
    const vectorRecord = {
        referenceName: pinnedReference.referenceName,
        canonicalMaterialFixture:
            'tools/lattigo-oracle/sealed-lattice-canonical-rns-fixtures.json',
        serializationSource: 'sealed-lattice-rust-wasm-canonical-rns-fixture',
        oracleVectorsAcceptedAsProtocolEvidence: false,
        protocolEvidenceUse: pinnedReference.protocolEvidenceUse,
    };
    const profileRecord = {
        referenceName: pinnedReference.referenceName,
        allowedUse: pinnedReference.allowedUse,
        claimBoundary: pinnedReference.claimBoundary,
        comparableScope: 'ring/RNS/NTT and coefficient arithmetic parity only',
        runtimeUse: pinnedReference.runtimeUse,
        protocolEvidenceUse: pinnedReference.protocolEvidenceUse,
    };

    return {
        referenceOracleCommitHash: deriveProtocolHash('ChallengeDomainHash', {
            payload: commitRecord,
            purpose: 'lattigo-reference-oracle-commit-v1',
        }),
        referenceOracleContainerHash: deriveProtocolHash(
            'ChallengeDomainHash',
            {
                payload: containerRecord,
                purpose: 'lattigo-reference-oracle-container-v1',
            },
        ),
        referenceOracleCommandHash: deriveProtocolHash('ChallengeDomainHash', {
            payload: commandRecord,
            purpose: 'lattigo-reference-oracle-command-v1',
        }),
        referenceOracleVectorRoot: deriveProtocolHash('ChallengeDomainHash', {
            payload: vectorRecord,
            purpose: 'lattigo-reference-oracle-vector-root-v1',
        }),
        referenceOracleProfileHash: deriveProtocolHash('ChallengeDomainHash', {
            payload: profileRecord,
            purpose: 'lattigo-reference-oracle-profile-v1',
        }),
        records: {
            commitRecord,
            containerRecord,
            commandRecord,
            vectorRecord,
            profileRecord,
        },
    };
};

export const verifyPinnedReference = async (): Promise<{
    readonly archivePresent: boolean;
    readonly checkoutPresent: boolean;
    readonly commandHash: string;
    readonly dockerfileHash: string;
    readonly referenceOracleHashBindings: ReferenceOracleHashBindings;
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
        const archiveHash = await sha256File(archiveAbsolutePath);
        archivePresent = true;
        assertPinnedHash('archive', archiveHash, pinnedReference.archiveSha256);
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
    const commandHash = sha256OracleCommandInputs(commandInputs);
    const dockerfileHash = sha256Text(dockerfile);
    assertPinnedHash(
        'oracle command',
        commandHash,
        pinnedReference.oracleCommandHash,
    );
    assertPinnedHash(
        'oracle Dockerfile',
        dockerfileHash,
        pinnedReference.oracleDockerfileHash,
    );

    return {
        archivePresent,
        checkoutPresent,
        commandHash,
        dockerfileHash,
        referenceOracleHashBindings: buildReferenceOracleHashBindings(
            pinnedReference,
            commandHash,
            dockerfileHash,
        ),
    };
};

const runDockerOracle = async (): Promise<void> => {
    await new Promise<void>((resolve, reject) => {
        const imageName = 'sealed-lattice-lattigo-oracle:bgv-rns';
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
            ['run', '--rm', 'sealed-lattice-lattigo-oracle:bgv-rns'],
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
                dockerOracleRun: true,
            },
            null,
            2,
        ),
    );

    await runDockerOracle();
};

if (isDirectlyInvokedModule(import.meta.url)) {
    void main();
}

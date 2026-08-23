import { spawnSync } from 'node:child_process';
import {
    mkdir,
    mkdtemp,
    readFile,
    rename,
    rm,
    writeFile,
} from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repositoryRoot = path.resolve(
    fileURLToPath(new URL('../../', import.meta.url)),
);
const regenerationScratchRoot = path.resolve(
    repositoryRoot,
    'temp',
    'compact-public-key-catalog-regeneration',
);
const kernelProofSuitePath = path.resolve(
    repositoryRoot,
    'crates',
    'sealed-lattice-kernel',
    'src',
    'bgv',
    'proof_suite',
);
const generatedArtifacts = [
    {
        fileName: 'compact_public_key_relation.generated.json',
        label: 'compact public-key relation catalog',
        targetPath: path.resolve(
            kernelProofSuitePath,
            'relation_plan',
            'compact_public_key_relation.generated.json',
        ),
    },
    {
        fileName: 'compact_public_key_assignment_source.generated.json',
        label: 'compact public-key assignment-source catalog',
        targetPath: path.resolve(
            kernelProofSuitePath,
            'relation_plan',
            'compact_public_key_assignment_source.generated.json',
        ),
    },
    {
        fileName: 'compact_proof_contract.generated.bin',
        label: 'compact public-key proof contract',
        targetPath: path.resolve(
            kernelProofSuitePath,
            'compact_proof_contract.generated.bin',
        ),
    },
] as const;

export type CompactPublicKeyCatalogRegenerationArguments = {
    readonly check: boolean;
};

export const parseCompactPublicKeyCatalogRegenerationArguments = (
    rawArguments: readonly string[],
): CompactPublicKeyCatalogRegenerationArguments => {
    if (rawArguments.length === 0) {
        return { check: false };
    }
    if (rawArguments.length === 1 && rawArguments[0] === '--check') {
        return { check: true };
    }
    throw new Error(
        'Usage: pnpm run generate:compact-public-key-catalogs [--check]',
    );
};

const runCargoRegenerationTest = (
    testFilter: string,
    outputDirectoryPath: string,
): void => {
    const result = spawnSync(
        'cargo',
        [
            'test',
            '--locked',
            '-p',
            'sealed-lattice-kernel',
            '--features',
            'compact-public-key-catalog-regeneration',
            testFilter,
            '--',
            '--nocapture',
        ],
        {
            cwd: repositoryRoot,
            env: {
                ...process.env,
                SEALED_LATTICE_COMPACT_PUBLIC_KEY_CATALOG_OUTPUT_DIRECTORY:
                    outputDirectoryPath,
            },
            encoding: 'utf8',
            maxBuffer: 100 * 1024 * 1024,
        },
    );
    if (result.error !== undefined) {
        throw new Error(
            `Failed to start compact public-key catalog regeneration: ${result.error.message}`,
        );
    }
    if (result.signal !== null || result.status !== 0) {
        const output = [result.stdout?.trim(), result.stderr?.trim()]
            .filter(Boolean)
            .join('\n');
        throw new Error(
            `Compact public-key catalog regeneration failed${result.signal === null ? ` with status ${result.status ?? 'null'}` : ` with signal ${result.signal}`}${output === '' ? '' : `\n${output}`}`,
        );
    }
};

export const assertCanonicalGeneratedJson = (
    bytes: Buffer,
    label: string,
): void => {
    const text = bytes.toString('utf8');
    if (!text.endsWith('\n') || text.endsWith('\n\n')) {
        throw new Error(`${label} must end in exactly one newline.`);
    }
    const canonicalText = `${JSON.stringify(JSON.parse(text.slice(0, -1)))}\n`;
    if (canonicalText !== text) {
        throw new Error(`${label} is not canonical single-line JSON.`);
    }
};

const replaceGeneratedArtifact = async (
    targetPath: string,
    bytes: Buffer,
): Promise<void> => {
    const temporaryPath = `${targetPath}.next`;
    try {
        await writeFile(temporaryPath, bytes);
        await rename(temporaryPath, targetPath);
    } finally {
        await rm(temporaryPath, { force: true });
    }
};

export const regenerateCompactPublicKeyCatalogs = async (
    rawArguments: readonly string[] = process.argv.slice(2),
): Promise<void> => {
    const { check } =
        parseCompactPublicKeyCatalogRegenerationArguments(rawArguments);
    await mkdir(regenerationScratchRoot, { recursive: true });
    const scratchDirectoryPath = await mkdtemp(
        path.join(regenerationScratchRoot, 'run-'),
    );
    if (path.dirname(scratchDirectoryPath) !== regenerationScratchRoot) {
        throw new Error(
            'Catalog regeneration scratch directory escaped its owner.',
        );
    }

    try {
        runCargoRegenerationTest(
            'generated_compact_public_key_catalog_regeneration_writes_canonical_compiler_output',
            scratchDirectoryPath,
        );
        for (const artifact of generatedArtifacts.slice(0, 2)) {
            const generatedBytes = await readFile(
                path.join(scratchDirectoryPath, artifact.fileName),
            );
            assertCanonicalGeneratedJson(generatedBytes, artifact.label);
            const currentBytes = await readFile(artifact.targetPath);
            if (!generatedBytes.equals(currentBytes)) {
                if (check) {
                    throw new Error(
                        `${artifact.label} is stale; run pnpm run generate:compact-public-key-catalogs.`,
                    );
                }
                await replaceGeneratedArtifact(
                    artifact.targetPath,
                    generatedBytes,
                );
            }
        }

        runCargoRegenerationTest(
            'generated_compact_public_key_contract_regeneration_writes_current_source',
            scratchDirectoryPath,
        );
        const contractArtifact = generatedArtifacts[2];
        const generatedContractBytes = await readFile(
            path.join(scratchDirectoryPath, contractArtifact.fileName),
        );
        const currentContractBytes = await readFile(
            contractArtifact.targetPath,
        );
        if (!generatedContractBytes.equals(currentContractBytes)) {
            if (check) {
                throw new Error(
                    `${contractArtifact.label} is stale; run pnpm run generate:compact-public-key-catalogs.`,
                );
            }
            await replaceGeneratedArtifact(
                contractArtifact.targetPath,
                generatedContractBytes,
            );
        }
    } finally {
        await rm(scratchDirectoryPath, { force: true, recursive: true });
    }
};

if (import.meta.main) {
    await regenerateCompactPublicKeyCatalogs();
}

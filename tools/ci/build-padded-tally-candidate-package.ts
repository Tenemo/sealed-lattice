import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
    copyFile,
    cp,
    mkdir,
    mkdtemp,
    readFile,
    readdir,
    rm,
    writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { runWithLocalRunLog, type ActiveLocalRunLog } from './local-run-log.js';
import {
    resolvePackageManagerRunner,
    resolvePackageManagerRunnerForPackageManager,
    type PackageManagerRunner,
} from './package-manager-runner.js';
import {
    runCommandAndCaptureOutput,
    type CommandInvocation,
} from './run-command.js';

import { completionProfileFinalityQuorum } from '#packages/wasm/src/finality-runtime.js';
import {
    maximumFoundationCopiedBufferByteLength,
    maximumFoundationWasmMemoryByteLength,
} from '#packages/wasm/src/foundation-contract.js';
import { sourceScoreEncodingCount } from '#packages/wasm/src/source-runtime.js';
import {
    compileIndependentPaddedTallyModel,
    encodeIndependentPaddedTallyCircuit,
    mapIndependentPaddedTallyCircuit,
    projectIndependentPaddedTallyWidth,
} from '#tests/padded-tally-transcript-model.js';

const repositoryRoot = fileURLToPath(new URL('../../', import.meta.url));
const candidateIdentityDomain =
    'sealed-lattice/candidate-package/content-identity/v1';
const parameterIdentityDomain =
    'sealed-lattice/candidate-package/parameter-identity/v1';
const identityByteLength = 64;
const operationLabelByteLength = 40;
const completionParticipantCount = 10;
const completionOptionCount = 10;
const scoreBitWidth = 4;
const maximumCorruptParticipantCount = 3;
const identityRecordRelativePath = 'candidate/candidate-build-identity.json';

type ContentEntry = Readonly<{
    bytes: Uint8Array;
    path: string;
}>;

type FileIdentity = Readonly<{
    byteLength: number;
    path: string;
    sha256Hex: string;
}>;

type PackMetadata = Readonly<{
    filename: string;
    files: readonly string[];
    integrity: string;
    name: string;
    version: string;
}>;

type CandidateKernelModule = Readonly<{
    instantiateConstructionKernelCommandRuntime: (
        kernelUrl: URL,
        options: Readonly<{ expectedKernelSha256Hex: string }>,
    ) => Promise<
        Readonly<{ executeCommand: (bytes: Uint8Array) => Uint8Array }>
    >;
}>;

type CandidatePaddedTallyModule = Readonly<{
    openPaddedTallyRuntime: (
        kernel: Readonly<{
            executeCommand: (bytes: Uint8Array) => Uint8Array;
        }>,
    ) => Readonly<{
        compilePlan: (topCount: number) => unknown;
    }>;
}>;

const toRepositoryPath = (value: string): string =>
    value.split(path.sep).join('/');

const encodeUnsigned64 = (value: number): Uint8Array => {
    if (!Number.isSafeInteger(value) || value < 0) {
        throw new RangeError('The content frame length is invalid.');
    }
    const bytes = new Uint8Array(8);
    new DataView(bytes.buffer).setBigUint64(0, BigInt(value), true);
    return bytes;
};

const updateFramedBytes = (
    hash: ReturnType<typeof createHash>,
    bytes: Uint8Array,
): void => {
    hash.update(encodeUnsigned64(bytes.byteLength));
    hash.update(bytes);
};

export const calculateCandidateContentIdentity = (
    entries: readonly ContentEntry[],
    domain = candidateIdentityDomain,
): string => {
    const sorted = [...entries].sort((left, right) =>
        left.path.localeCompare(right.path, 'en'),
    );
    const duplicatePaths = sorted.filter(
        (entry, index) => entry.path === sorted[index - 1]?.path,
    );
    if (duplicatePaths.length > 0) {
        throw new Error(
            `Candidate content repeats ${duplicatePaths[0]?.path ?? 'a path'}.`,
        );
    }
    const hash = createHash('shake256', { outputLength: identityByteLength });
    updateFramedBytes(hash, new TextEncoder().encode(domain));
    hash.update(encodeUnsigned64(sorted.length));
    for (const entry of sorted) {
        const entryPath = new TextEncoder().encode(entry.path);
        updateFramedBytes(hash, entryPath);
        updateFramedBytes(hash, entry.bytes);
    }
    return hash.digest('hex');
};

const sortJsonValue = (value: unknown): unknown => {
    if (Array.isArray(value)) return value.map(sortJsonValue);
    if (value !== null && typeof value === 'object') {
        return Object.fromEntries(
            Object.entries(value)
                .sort(([left], [right]) => left.localeCompare(right, 'en'))
                .map(([key, entry]) => [key, sortJsonValue(entry)]),
        );
    }
    return value;
};

export const serializeCandidateJson = (value: unknown): Uint8Array =>
    new TextEncoder().encode(
        `${JSON.stringify(sortJsonValue(value), null, 2)}\n`,
    );

const sha256Hex = (bytes: Uint8Array): string =>
    createHash('sha256').update(bytes).digest('hex');

const identifyBytes = (
    relativePath: string,
    bytes: Uint8Array,
): FileIdentity => ({
    byteLength: bytes.byteLength,
    path: relativePath,
    sha256Hex: sha256Hex(bytes),
});

const listFiles = async (directoryPath: string): Promise<string[]> => {
    const entries = await readdir(directoryPath, { withFileTypes: true });
    const files: string[] = [];
    for (const entry of entries) {
        const entryPath = path.join(directoryPath, entry.name);
        if (entry.isDirectory()) files.push(...(await listFiles(entryPath)));
        else if (entry.isFile()) files.push(entryPath);
    }
    return files;
};

const readContentEntries = async (
    directoryPath: string,
    excludedRelativePaths: ReadonlySet<string> = new Set(),
): Promise<ContentEntry[]> => {
    const entries: ContentEntry[] = [];
    for (const filePath of await listFiles(directoryPath)) {
        const relativePath = toRepositoryPath(
            path.relative(directoryPath, filePath),
        );
        if (!excludedRelativePaths.has(relativePath)) {
            entries.push({
                bytes: Uint8Array.from(await readFile(filePath)),
                path: relativePath,
            });
        }
    }
    return entries.sort((left, right) =>
        left.path.localeCompare(right.path, 'en'),
    );
};

const runCommand = async (
    runLog: ActiveLocalRunLog,
    invocation: CommandInvocation,
): Promise<string> => {
    const result = await runCommandAndCaptureOutput(invocation, { runLog });
    if (result.exitCode !== 0 || result.terminationSignal !== null) {
        const output = [result.stdout.trim(), result.stderr.trim()]
            .filter(Boolean)
            .join('\n');
        throw new Error(
            `${invocation.description} failed${
                output.length === 0 ? '.' : `:\n${output}`
            }`,
        );
    }
    return result.stdout;
};

const runPackageManager = (
    runLog: ActiveLocalRunLog,
    runner: PackageManagerRunner,
    arguments_: readonly string[],
    input: Readonly<{
        description: string;
        environment?: NodeJS.ProcessEnv;
        workingDirectoryPath: string;
    }>,
): Promise<string> =>
    runCommand(runLog, {
        args: [...runner.commandArgumentsPrefix, ...arguments_],
        command: runner.command,
        description: input.description,
        env: input.environment,
        workingDirectoryPath: input.workingDirectoryPath,
    });

const repositoryStatus = (): string =>
    execFileSync(
        'git',
        [
            'status',
            '--porcelain=v1',
            '--untracked-files=normal',
            '--ignore-submodules=none',
        ],
        { cwd: repositoryRoot, encoding: 'utf8', windowsHide: true },
    );

const requireCleanRepository = (): string => {
    const status = repositoryStatus();
    if (status.length > 0) {
        throw new Error(
            'The candidate package must be built from a clean tracked worktree.',
        );
    }
    return execFileSync('git', ['rev-parse', '--verify', 'HEAD^{commit}'], {
        cwd: repositoryRoot,
        encoding: 'utf8',
        windowsHide: true,
    }).trim();
};

const trackedSourcePaths = (): string[] => {
    const tracked = execFileSync('git', ['ls-files', '-z'], {
        cwd: repositoryRoot,
        encoding: 'utf8',
        maxBuffer: 100 * 1024 * 1024,
        windowsHide: true,
    })
        .split('\0')
        .filter(Boolean);
    const exactBuildInputs = new Set([
        'Cargo.lock',
        'Cargo.toml',
        'package.json',
        'pnpm-lock.yaml',
        'tsconfig.base.json',
        'tsconfig.json',
        'tsconfig.tools.json',
        'vitest.config.ts',
    ]);
    return tracked
        .filter(
            (relativePath) =>
                exactBuildInputs.has(relativePath) ||
                relativePath === 'crates/sealed-lattice-kernel/Cargo.toml' ||
                relativePath.startsWith('crates/sealed-lattice-kernel/src/') ||
                relativePath === 'packages/sdk/package.json' ||
                relativePath === 'packages/sdk/tsconfig.json' ||
                relativePath.startsWith('packages/sdk/src/') ||
                relativePath === 'packages/wasm/package.json' ||
                relativePath === 'packages/wasm/tsconfig.json' ||
                relativePath.startsWith('packages/wasm/src/') ||
                relativePath.startsWith('packages/wasm/tests/') ||
                relativePath.startsWith('tests/') ||
                relativePath.startsWith('tools/ci/'),
        )
        .sort((left, right) => left.localeCompare(right, 'en'));
};

const sourceRole = (relativePath: string): string => {
    if (relativePath.startsWith('crates/sealed-lattice-kernel/src/')) {
        return 'rust-generator-verifier-and-vectors';
    }
    if (relativePath.startsWith('packages/wasm/src/')) {
        return 'worker-and-webassembly-bridge';
    }
    if (relativePath.startsWith('packages/sdk/src/')) {
        return 'public-fail-closed-boundary';
    }
    if (
        relativePath.startsWith('tests/') ||
        relativePath.startsWith('packages/wasm/tests/')
    ) {
        return 'independent-model-positive-and-hostile-cases';
    }
    return 'build-and-verification-input';
};

const readSourceIdentities = async (): Promise<
    readonly (FileIdentity & Readonly<{ role: string }>)[]
> =>
    Promise.all(
        trackedSourcePaths().map(async (relativePath) => {
            const bytes = Uint8Array.from(
                await readFile(path.join(repositoryRoot, relativePath)),
            );
            return {
                ...identifyBytes(relativePath, bytes),
                role: sourceRole(relativePath),
            };
        }),
    );

const sourceLineNumber = (source: string, offset: number): number =>
    source.slice(0, offset).split('\n').length;

const extractFunctionalDomains = async (
    sourceIdentities: readonly FileIdentity[],
): Promise<
    readonly Readonly<{ domain: string; sources: readonly string[] }>[]
> => {
    const sourcePathsByDomain = new Map<string, Set<string>>();
    for (const identity of sourceIdentities) {
        if (
            !identity.path.startsWith('crates/sealed-lattice-kernel/src/') &&
            !identity.path.startsWith('packages/wasm/src/')
        ) {
            continue;
        }
        const source = await readFile(
            path.join(repositoryRoot, identity.path),
            'utf8',
        );
        for (const match of source.matchAll(
            /sealed-lattice\/[A-Za-z0-9._/-]+\/v[0-9]+/gu,
        )) {
            const domain = match[0];
            if (domain.includes('/test/')) continue;
            const paths = sourcePathsByDomain.get(domain) ?? new Set<string>();
            paths.add(identity.path);
            sourcePathsByDomain.set(domain, paths);
        }
    }
    return [...sourcePathsByDomain.entries()]
        .sort(([left], [right]) => left.localeCompare(right, 'en'))
        .map(([domain, sources]) => ({
            domain,
            sources: [...sources].sort((left, right) =>
                left.localeCompare(right, 'en'),
            ),
        }));
};

const extractProtocolNumericConstants = async (
    sourceIdentities: readonly FileIdentity[],
): Promise<
    readonly Readonly<{
        line: number;
        name: string;
        path: string;
        value: number;
    }>[]
> => {
    const constants: Array<{
        line: number;
        name: string;
        path: string;
        value: number;
    }> = [];
    const constantPattern =
        /(?:pub(?:\(crate\))?\s+)?const\s+([A-Za-z][A-Za-z0-9_]*)\s*(?::[^=;]+)?=\s*(0x[0-9A-Fa-f_]+|[0-9][0-9_]*)\s*;/gu;
    const inventoryNamePattern =
        /(schema|command|object.*kind|state.*kind|ordinal)/iu;
    for (const identity of sourceIdentities) {
        if (
            !identity.path.startsWith('crates/sealed-lattice-kernel/src/') &&
            !identity.path.startsWith('packages/wasm/src/')
        ) {
            continue;
        }
        const source = await readFile(
            path.join(repositoryRoot, identity.path),
            'utf8',
        );
        for (const match of source.matchAll(constantPattern)) {
            const name = match[1];
            const literal = match[2];
            if (
                name === undefined ||
                literal === undefined ||
                !inventoryNamePattern.test(name)
            ) {
                continue;
            }
            constants.push({
                line: sourceLineNumber(source, match.index),
                name,
                path: identity.path,
                value: Number(literal.replace(/_/gu, '')),
            });
        }
    }
    return constants.sort(
        (left, right) =>
            left.path.localeCompare(right.path, 'en') ||
            left.line - right.line ||
            left.name.localeCompare(right.name, 'en'),
    );
};

const expectedPlan = (topCount: number): unknown => {
    const model = compileIndependentPaddedTallyModel(topCount);
    const projection = projectIndependentPaddedTallyWidth(
        model,
        operationLabelByteLength,
    );
    return {
        participantCount: completionParticipantCount,
        optionCount: completionOptionCount,
        topCount,
        inputWireCount: model.inputWireCount,
        operationCount: model.operations.length,
        constantCount: model.constantCount,
        linearCount: model.linearCount,
        conjunctionCount: model.conjunctionCount,
        negationCount: model.negationCount,
        outputCount: model.outputWires.length,
        wireCount: model.inputWireCount + model.operations.length,
        logicalPayloadByteLength: model.logicalPayloadByteLength,
        labelEntropyByteLength: model.labelEntropyByteLength,
        manifestByteLength: projection.manifestByteLength,
        maximumLiveWireCount: model.maximumLiveWireCount,
        chunks: model.descriptors.map((descriptor, index) => ({
            chunkByteLength: descriptor.chunkByteLength,
            labelEntropyByteLength: descriptor.labelEntropyByteLength,
            liveWireCountAfterChunk: model.liveWireCountsAfterChunks[index],
        })),
    };
};

const requireExactValue = (
    actual: unknown,
    expected: unknown,
    description: string,
): void => {
    if (
        JSON.stringify(sortJsonValue(actual)) !==
        JSON.stringify(sortJsonValue(expected))
    ) {
        throw new Error(`${description} differs from the independent model.`);
    }
};

const wasmExportNames = (bytes: Uint8Array): readonly string[] =>
    WebAssembly.Module.exports(
        new WebAssembly.Module(Uint8Array.from(bytes).buffer),
    )
        .map((entry) => entry.name)
        .sort((left, right) => left.localeCompare(right, 'en'));

const requireKernelBoundaries = async (): Promise<
    Readonly<{
        candidateKernel: FileIdentity;
        candidateWasmExports: readonly string[];
        publicKernel: FileIdentity;
        publicWasmExports: readonly string[];
    }>
> => {
    const candidatePath = path.join(
        repositoryRoot,
        'packages',
        'wasm',
        'dist',
        'sealed-lattice-kernel.wasm',
    );
    const publicPath = path.join(
        repositoryRoot,
        'packages',
        'sdk',
        'dist',
        'sealed-lattice-kernel.wasm',
    );
    const candidateBytes = Uint8Array.from(await readFile(candidatePath));
    const publicBytes = Uint8Array.from(await readFile(publicPath));
    const candidateWasmExports = wasmExportNames(candidateBytes);
    const publicWasmExports = wasmExportNames(publicBytes);
    if (
        !candidateWasmExports.includes(
            'sealed_lattice_construction_command_with_length',
        )
    ) {
        throw new Error(
            'The internal candidate omits its construction command.',
        );
    }
    if (
        publicWasmExports.includes(
            'sealed_lattice_construction_command_with_length',
        )
    ) {
        throw new Error('The public package exposes the construction command.');
    }
    return {
        candidateKernel: identifyBytes(
            'dist/sealed-lattice-kernel.wasm',
            candidateBytes,
        ),
        candidateWasmExports,
        publicKernel: identifyBytes(
            'packages/sdk/dist/sealed-lattice-kernel.wasm',
            publicBytes,
        ),
        publicWasmExports,
    };
};

const writeCircuitArtifacts = async (
    rustCircuitDirectoryPath: string,
    candidateDirectoryPath: string,
): Promise<readonly Readonly<Record<string, unknown>>[]> => {
    const circuitDirectoryPath = path.join(candidateDirectoryPath, 'circuits');
    const mappingDirectoryPath = path.join(candidateDirectoryPath, 'mappings');
    await Promise.all([
        mkdir(circuitDirectoryPath, { recursive: true }),
        mkdir(mappingDirectoryPath, { recursive: true }),
    ]);
    const circuits: Array<Readonly<Record<string, unknown>>> = [];
    for (let topCount = 1; topCount <= completionOptionCount; topCount += 1) {
        const name = `top-count-${String(topCount).padStart(2, '0')}`;
        const rustBytes = Uint8Array.from(
            await readFile(
                path.join(rustCircuitDirectoryPath, `${name}.circuit.bin`),
            ),
        );
        const model = compileIndependentPaddedTallyModel(topCount);
        const independentBytes = encodeIndependentPaddedTallyCircuit(model);
        if (
            rustBytes.byteLength !== independentBytes.byteLength ||
            !rustBytes.every(
                (value, index) => value === independentBytes[index],
            )
        ) {
            throw new Error(
                `Rust and the independent model disagree for topCount ${String(topCount)}.`,
            );
        }
        const circuitRelativePath = `candidate/circuits/${name}.circuit.bin`;
        const mappingRelativePath = `candidate/mappings/${name}.mapping.json`;
        const mappingBytes = serializeCandidateJson(
            mapIndependentPaddedTallyCircuit(model),
        );
        await Promise.all([
            writeFile(
                path.join(circuitDirectoryPath, `${name}.circuit.bin`),
                rustBytes,
                { flag: 'wx' },
            ),
            writeFile(
                path.join(mappingDirectoryPath, `${name}.mapping.json`),
                mappingBytes,
                { flag: 'wx' },
            ),
        ]);
        circuits.push({
            topCount,
            circuit: identifyBytes(circuitRelativePath, rustBytes),
            mapping: identifyBytes(mappingRelativePath, mappingBytes),
            plan: expectedPlan(topCount),
        });
    }
    return circuits;
};

const stageCandidatePackage = async (
    packageDirectoryPath: string,
    rustCircuitDirectoryPath: string,
    repositoryCommitHash: string,
): Promise<
    Readonly<{
        candidateBuildIdentityHex: string;
        candidateKernelSha256Hex: string;
        parameterIdentityHex: string;
    }>
> => {
    const sourcePackagePath = path.join(repositoryRoot, 'packages', 'wasm');
    const candidateDirectoryPath = path.join(packageDirectoryPath, 'candidate');
    await mkdir(candidateDirectoryPath, { recursive: true });
    await Promise.all([
        cp(
            path.join(sourcePackagePath, 'dist'),
            path.join(packageDirectoryPath, 'dist'),
            { recursive: true },
        ),
        copyFile(
            path.join(repositoryRoot, 'README.md'),
            path.join(packageDirectoryPath, 'README.md'),
        ),
        copyFile(
            path.join(repositoryRoot, 'LICENSE'),
            path.join(packageDirectoryPath, 'LICENSE'),
        ),
    ]);
    await rm(path.join(packageDirectoryPath, 'dist', 'tsconfig.tsbuildinfo'), {
        force: true,
    });

    const packageManifest = JSON.parse(
        await readFile(path.join(sourcePackagePath, 'package.json'), 'utf8'),
    ) as Record<string, unknown>;
    delete packageManifest.devDependencies;
    delete packageManifest.scripts;
    packageManifest.files = ['candidate', 'dist', 'LICENSE', 'README.md'];
    await writeFile(
        path.join(packageDirectoryPath, 'package.json'),
        serializeCandidateJson(packageManifest),
        { flag: 'wx' },
    );

    const circuits = await writeCircuitArtifacts(
        rustCircuitDirectoryPath,
        candidateDirectoryPath,
    );
    const sourceIdentities = await readSourceIdentities();
    const functionalDomains = await extractFunctionalDomains(sourceIdentities);
    const protocolNumericConstants =
        await extractProtocolNumericConstants(sourceIdentities);
    const maximumProjection = projectIndependentPaddedTallyWidth(
        compileIndependentPaddedTallyModel(completionOptionCount),
        operationLabelByteLength,
    );
    const parameters = {
        completionProfile: {
            participantCount: completionParticipantCount,
            optionCount: completionOptionCount,
            admittedTopCounts: Array.from(
                { length: completionOptionCount },
                (_, index) => index + 1,
            ),
            maximumCorruptParticipantCount,
            directFinalityQuorum: completionProfileFinalityQuorum,
            scoreBitWidth,
            sourceScoreEncodingCount,
        },
        construction: {
            operationLabelByteLength,
            constructionCommandOrdinals: [42, 43, 44, 45, 46, 47],
            transcriptVersion: 1,
        },
        parserAndAllocationBounds: {
            maximumCopiedBufferByteLength:
                maximumFoundationCopiedBufferByteLength,
            maximumWasmMemoryByteLength: maximumFoundationWasmMemoryByteLength,
            maximumChunkByteLength: maximumProjection.maximumChunkByteLength,
            maximumChunkEvaluationRequestByteLength:
                maximumProjection.maximumChunkEvaluationRequestByteLength,
        },
        functionalDomains,
        protocolNumericConstants,
    };
    const parameterBytes = serializeCandidateJson(parameters);
    const parameterIdentityHex = calculateCandidateContentIdentity(
        [{ bytes: parameterBytes, path: 'parameters.json' }],
        parameterIdentityDomain,
    );
    const kernelBoundaries = await requireKernelBoundaries();
    const candidateBundle = {
        schema: 'sealed-lattice-internal-candidate-bundle',
        schemaVersion: 1,
        repositoryCommitHash,
        identityRules: {
            candidateBuildIdentity: {
                algorithm: 'SHAKE256-512',
                domain: candidateIdentityDomain,
                excludedSelfRecord: identityRecordRelativePath,
            },
            parameterIdentity: {
                algorithm: 'SHAKE256-512',
                domain: parameterIdentityDomain,
                identityHex: parameterIdentityHex,
            },
        },
        packageBoundary: {
            packageName: packageManifest.name,
            packageVersion: packageManifest.version,
            rootExport: 'foundation-only',
            existingConstructionRuntime: 'dist/padded-tally-runtime.js',
            existingWorkerRuntime: 'dist/private-preparation-worker-runtime.js',
            publicKernel: kernelBoundaries.publicKernel,
            publicWasmExports: kernelBoundaries.publicWasmExports,
            candidateKernel: kernelBoundaries.candidateKernel,
            candidateWasmExports: kernelBoundaries.candidateWasmExports,
        },
        parameters,
        circuits,
        canonicalCaseSourceIdentities: sourceIdentities.filter(
            (identity) =>
                identity.role ===
                    'independent-model-positive-and-hostile-cases' ||
                identity.path.endsWith('/tests.rs') ||
                identity.path.endsWith('.kernel.test.ts') ||
                identity.path.endsWith('.browser.test.ts'),
        ),
        sourceIdentities,
    };
    await writeFile(
        path.join(candidateDirectoryPath, 'candidate-bundle.json'),
        serializeCandidateJson(candidateBundle),
        { flag: 'wx' },
    );

    const coveredEntries = await readContentEntries(packageDirectoryPath);
    const candidateBuildIdentityHex =
        calculateCandidateContentIdentity(coveredEntries);
    const identityRecord = {
        algorithm: 'SHAKE256-512',
        domain: candidateIdentityDomain,
        identityHex: candidateBuildIdentityHex,
        excludedSelfRecord: identityRecordRelativePath,
        coveredFiles: coveredEntries.map((entry) =>
            identifyBytes(entry.path, entry.bytes),
        ),
    };
    await writeFile(
        path.join(packageDirectoryPath, identityRecordRelativePath),
        serializeCandidateJson(identityRecord),
        { flag: 'wx' },
    );
    return {
        candidateBuildIdentityHex,
        candidateKernelSha256Hex: kernelBoundaries.candidateKernel.sha256Hex,
        parameterIdentityHex,
    };
};

const parsePackMetadata = (output: string): PackMetadata => {
    const parsed = JSON.parse(output) as unknown;
    if (!Array.isArray(parsed) || parsed.length !== 1) {
        throw new Error('npm pack returned an unexpected candidate result.');
    }
    const entry: unknown = parsed[0];
    if (typeof entry !== 'object' || entry === null) {
        throw new Error('npm pack omitted candidate metadata.');
    }
    const record = entry as Record<string, unknown>;
    if (
        typeof record.filename !== 'string' ||
        typeof record.integrity !== 'string' ||
        typeof record.name !== 'string' ||
        typeof record.version !== 'string' ||
        !Array.isArray(record.files)
    ) {
        throw new Error('npm pack returned malformed candidate metadata.');
    }
    const files = record.files.map((file) => {
        if (
            typeof file !== 'object' ||
            file === null ||
            typeof (file as Record<string, unknown>).path !== 'string'
        ) {
            throw new Error('npm pack returned a malformed candidate file.');
        }
        return (file as Readonly<{ path: string }>).path;
    });
    return {
        filename: record.filename,
        files,
        integrity: record.integrity,
        name: record.name,
        version: record.version,
    };
};

const npmEnvironment = (cacheDirectoryPath: string): NodeJS.ProcessEnv => ({
    ...Object.fromEntries(
        Object.entries(process.env).filter(
            ([name]) => name.toLowerCase() !== 'npm_config_cache',
        ),
    ),
    npm_config_cache: cacheDirectoryPath,
});

const verifyPackedCandidate = async (
    packageDirectoryPath: string,
    consumerDirectoryPath: string,
    tarballPath: string,
    identity: Readonly<{
        candidateBuildIdentityHex: string;
        candidateKernelSha256Hex: string;
    }>,
): Promise<void> => {
    const installedPackagePath = path.join(
        consumerDirectoryPath,
        'node_modules',
        '@sealed-lattice',
        'wasm',
    );
    const rootModule = (await import(
        pathToFileURL(path.join(installedPackagePath, 'dist', 'index.js')).href
    )) as Record<string, unknown>;
    if (
        'openPaddedTallyRuntime' in rootModule ||
        'installPrivatePreparationWorker' in rootModule
    ) {
        throw new Error(
            'The candidate root export exposes construction dispatch.',
        );
    }
    const workerModule = (await import(
        pathToFileURL(
            path.join(
                installedPackagePath,
                'dist',
                'private-preparation-worker-runtime.js',
            ),
        ).href
    )) as Record<string, unknown>;
    if (typeof workerModule.installPrivatePreparationWorker !== 'function') {
        throw new Error('The packaged existing worker runtime is absent.');
    }
    const kernelModule = (await import(
        pathToFileURL(
            path.join(
                installedPackagePath,
                'dist',
                'foundation-kernel',
                'kernel-runtime.js',
            ),
        ).href
    )) as CandidateKernelModule;
    const paddedTallyModule = (await import(
        pathToFileURL(
            path.join(installedPackagePath, 'dist', 'padded-tally-runtime.js'),
        ).href
    )) as CandidatePaddedTallyModule;
    const kernel =
        await kernelModule.instantiateConstructionKernelCommandRuntime(
            pathToFileURL(
                path.join(
                    installedPackagePath,
                    'dist',
                    'sealed-lattice-kernel.wasm',
                ),
            ),
            {
                expectedKernelSha256Hex: identity.candidateKernelSha256Hex,
            },
        );
    const runtime = paddedTallyModule.openPaddedTallyRuntime(kernel);
    for (let topCount = 1; topCount <= completionOptionCount; topCount += 1) {
        requireExactValue(
            runtime.compilePlan(topCount),
            expectedPlan(topCount),
            `Packaged topCount ${String(topCount)} plan`,
        );
    }

    const identityRecordExclusion = new Set([identityRecordRelativePath]);
    const installedEntries = await readContentEntries(
        installedPackagePath,
        identityRecordExclusion,
    );
    const recomputedIdentity =
        calculateCandidateContentIdentity(installedEntries);
    if (recomputedIdentity !== identity.candidateBuildIdentityHex) {
        throw new Error('The installed candidate content identity changed.');
    }
    if (!(await readFile(tarballPath)).byteLength) {
        throw new Error('The candidate tarball is empty.');
    }
    const stagedEntries = await readContentEntries(
        packageDirectoryPath,
        identityRecordExclusion,
    );
    if (
        calculateCandidateContentIdentity(stagedEntries) !==
        identity.candidateBuildIdentityHex
    ) {
        throw new Error('The staged candidate content identity changed.');
    }
};

const buildCandidatePackage = async (
    runLog: ActiveLocalRunLog,
): Promise<void> => {
    const repositoryCommitHash = requireCleanRepository();
    const temporaryRoot = await mkdtemp(
        path.join(tmpdir(), 'sealed-lattice-candidate-'),
    );
    const packageDirectoryPath = path.join(temporaryRoot, 'package');
    const rustCircuitDirectoryPath = path.join(temporaryRoot, 'rust-circuits');
    const consumerDirectoryPath = path.join(temporaryRoot, 'consumer');
    const attachmentsDirectoryPath = path.join(
        runLog.runDirectoryPath,
        'attachments',
    );
    const npmCacheDirectoryPath = path.join(temporaryRoot, 'npm-cache');
    const packageManagerRunner = resolvePackageManagerRunner();
    const npmRunner = resolvePackageManagerRunnerForPackageManager('npm');
    try {
        await runPackageManager(
            runLog,
            packageManagerRunner,
            ['run', 'build'],
            {
                description: 'Build the exact workspace candidate inputs',
                workingDirectoryPath: repositoryRoot,
            },
        );
        await runCommand(runLog, {
            args: [
                'test',
                '-p',
                'sealed-lattice-kernel',
                'exports_exact_completion_profile_circuit_bytes_when_requested',
                '--',
                '--nocapture',
            ],
            command: 'cargo',
            description: 'Export exact Rust completion circuits',
            env: {
                ...process.env,
                SEALED_LATTICE_CANDIDATE_CIRCUIT_DIRECTORY:
                    rustCircuitDirectoryPath,
            },
            workingDirectoryPath: repositoryRoot,
        });
        const identity = await stageCandidatePackage(
            packageDirectoryPath,
            rustCircuitDirectoryPath,
            repositoryCommitHash,
        );
        if (repositoryStatus().length > 0) {
            throw new Error(
                'The candidate build changed the tracked worktree.',
            );
        }

        await mkdir(attachmentsDirectoryPath, { recursive: true });
        const npmEnvironmentVariables = npmEnvironment(npmCacheDirectoryPath);
        const packed = parsePackMetadata(
            await runPackageManager(
                runLog,
                npmRunner,
                [
                    'pack',
                    '--json',
                    '--ignore-scripts',
                    '--pack-destination',
                    attachmentsDirectoryPath,
                ],
                {
                    description: 'Create the internal candidate tarball',
                    environment: npmEnvironmentVariables,
                    workingDirectoryPath: packageDirectoryPath,
                },
            ),
        );
        const expectedFiles = (await readContentEntries(packageDirectoryPath))
            .map((entry) => entry.path)
            .sort((left, right) => left.localeCompare(right, 'en'));
        const packedFiles = [...packed.files].sort((left, right) =>
            left.localeCompare(right, 'en'),
        );
        requireExactValue(
            packedFiles,
            expectedFiles,
            'Candidate tarball file inventory',
        );
        const tarballPath = path.join(
            attachmentsDirectoryPath,
            packed.filename,
        );
        await mkdir(consumerDirectoryPath, { recursive: true });
        await writeFile(
            path.join(consumerDirectoryPath, 'package.json'),
            serializeCandidateJson({
                name: 'sealed-lattice-candidate-verifier',
                private: true,
                type: 'module',
            }),
            { flag: 'wx' },
        );
        await runPackageManager(
            runLog,
            npmRunner,
            ['install', '--ignore-scripts', tarballPath],
            {
                description:
                    'Install the candidate tarball in an empty consumer',
                environment: npmEnvironmentVariables,
                workingDirectoryPath: consumerDirectoryPath,
            },
        );
        await verifyPackedCandidate(
            packageDirectoryPath,
            consumerDirectoryPath,
            tarballPath,
            identity,
        );
        const tarballBytes = Uint8Array.from(await readFile(tarballPath));
        const result = {
            repositoryCommitHash,
            candidateBuildIdentityHex: identity.candidateBuildIdentityHex,
            parameterIdentityHex: identity.parameterIdentityHex,
            tarball: identifyBytes(
                `attachments/${packed.filename}`,
                tarballBytes,
            ),
            npmIntegrity: packed.integrity,
            packageName: packed.name,
            packageVersion: packed.version,
            rootExport: 'foundation-only',
            constructionExercise: {
                topCounts: Array.from(
                    { length: completionOptionCount },
                    (_, index) => index + 1,
                ),
                runtimeModule: 'dist/padded-tally-runtime.js',
                workerModule: 'dist/private-preparation-worker-runtime.js',
            },
        };
        await writeFile(
            path.join(runLog.runDirectoryPath, 'candidate-package.json'),
            serializeCandidateJson(result),
            { flag: 'wx' },
        );
        runLog.writeEvent({
            details: result,
            eventType: 'candidate-package-verified',
        });
        process.stdout.write(
            `Candidate package verified at ${runLog.runDirectoryPath}\n`,
        );
    } finally {
        await rm(temporaryRoot, { force: true, recursive: true });
    }
};

const main = async (): Promise<void> => {
    if (process.argv.length !== 2) {
        throw new Error(
            'The candidate package builder accepts no command-line arguments.',
        );
    }
    await runWithLocalRunLog(
        {
            commandLineArguments: [],
            lanes: ['Internal candidate package and correspondence'],
            scriptName: 'build-padded-tally-candidate-package',
        },
        buildCandidatePackage,
    );
};

if (import.meta.main) void main();

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
import { paddedTallyMaximumChunkByteLength } from '#packages/wasm/src/padded-tally-runtime.js';
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
        'packages/sdk/package.json',
        'packages/sdk/tsconfig.json',
        'packages/wasm/package.json',
        'packages/wasm/tsconfig.json',
        'tests/padded-tally-transcript-model.ts',
        'tools/ci/build-padded-tally-candidate-package.ts',
        'tools/ci/build-wasm-kernel.ts',
        'tsconfig.base.json',
        'tsconfig.json',
        'tsconfig.tools.json',
    ]);
    return tracked
        .filter(
            (relativePath) =>
                exactBuildInputs.has(relativePath) ||
                relativePath === 'crates/sealed-lattice-kernel/Cargo.toml' ||
                relativePath.startsWith('crates/sealed-lattice-kernel/src/') ||
                relativePath.startsWith('packages/sdk/src/') ||
                relativePath.startsWith('packages/wasm/src/'),
        )
        .sort((left, right) => left.localeCompare(right, 'en'));
};

const sourceRole = (relativePath: string): string => {
    if (relativePath.startsWith('crates/sealed-lattice-kernel/src/')) {
        return 'rust-generator-and-verifier';
    }
    if (relativePath.startsWith('packages/wasm/src/')) {
        return 'worker-and-webassembly-bridge';
    }
    if (relativePath.startsWith('packages/sdk/src/')) {
        return 'public-fail-closed-boundary';
    }
    if (relativePath === 'tests/padded-tally-transcript-model.ts') {
        return 'independent-circuit-and-mapping-generator';
    }
    if (relativePath === 'tools/ci/build-padded-tally-candidate-package.ts') {
        return 'candidate-bundle-and-vector-generator';
    }
    if (relativePath === 'tools/ci/build-wasm-kernel.ts') {
        return 'webassembly-build-generator';
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

const productionSourceText = (relativePath: string, source: string): string => {
    if (!relativePath.endsWith('.rs')) return source;
    const testModuleOffset = source.search(
        /(?:^|\n)#\[cfg\(test\)\]\r?\nmod tests\s*\{/u,
    );
    return testModuleOffset < 0 ? source : source.slice(0, testModuleOffset);
};

const parseNumericLiteral = (literal: string): number =>
    Number(literal.replace(/_/gu, ''));

const extractProtocolGrammar = async (
    sourceIdentities: readonly FileIdentity[],
): Promise<Readonly<Record<string, unknown>>> => {
    const sourcePathsByDomain = new Map<string, Set<string>>();
    const namedCodes: Array<{
        line: number;
        name: string;
        path: string;
        value: number;
    }> = [];
    const enumeratedCodes: Array<{
        enumName: string;
        line: number;
        name: string;
        path: string;
        representation: string;
        value: number;
    }> = [];
    const magicBytes: Array<{
        ascii: string;
        hex: string;
        line: number;
        name: string;
        path: string;
    }> = [];
    const constantPattern =
        /(?:pub(?:\(crate\))?\s+)?const\s+([A-Za-z][A-Za-z0-9_]*)\s*(?::[^=;]+)?=\s*(0x[0-9A-Fa-f_]+|[0-9][0-9_]*)\s*;/gu;
    const codeNamePattern =
        /(schema|command|object.*kind|state.*kind|ordinal|version|family|address|purpose|declaration|target.*kind|result.*kind|operation.*kind)/iu;
    const enumerationPattern =
        /#\[repr\((u8|u16|u32)\)\]\s*(?:pub(?:\([^)]*\))?\s+)?enum\s+([A-Za-z][A-Za-z0-9_]*)\s*\{([^}]+)\}/gu;
    const enumerationValuePattern =
        /([A-Za-z][A-Za-z0-9_]*)\s*=\s*(0x[0-9A-Fa-f_]+|[0-9][0-9_]*)/gu;
    const magicPattern =
        /const\s+([A-Za-z][A-Za-z0-9_]*MAGIC)\s*:\s*\[u8;\s*[0-9]+\]\s*=\s*\*b"([ -~]+)"\s*;/gu;
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
        const productionSource = productionSourceText(identity.path, source);
        for (const match of productionSource.matchAll(
            /sealed-lattice(?:\/|\.)[A-Za-z0-9._/-]+(?:\/v[0-9]+|\.v[0-9]+)/gu,
        )) {
            const domain = match[0];
            if (domain === undefined || domain.includes('/test/')) continue;
            const paths = sourcePathsByDomain.get(domain) ?? new Set<string>();
            paths.add(identity.path);
            sourcePathsByDomain.set(domain, paths);
        }
        for (const match of productionSource.matchAll(constantPattern)) {
            const name = match[1];
            const literal = match[2];
            if (
                name === undefined ||
                literal === undefined ||
                !codeNamePattern.test(name)
            ) {
                continue;
            }
            namedCodes.push({
                line: sourceLineNumber(source, match.index),
                name,
                path: identity.path,
                value: parseNumericLiteral(literal),
            });
        }
        for (const enumeration of productionSource.matchAll(
            enumerationPattern,
        )) {
            const representation = enumeration[1];
            const enumName = enumeration[2];
            const body = enumeration[3];
            if (
                representation === undefined ||
                enumName === undefined ||
                body === undefined
            ) {
                continue;
            }
            for (const valueMatch of body.matchAll(enumerationValuePattern)) {
                const name = valueMatch[1];
                const literal = valueMatch[2];
                if (name === undefined || literal === undefined) continue;
                enumeratedCodes.push({
                    enumName,
                    line: sourceLineNumber(
                        source,
                        enumeration.index + valueMatch.index,
                    ),
                    name,
                    path: identity.path,
                    representation,
                    value: parseNumericLiteral(literal),
                });
            }
        }
        for (const match of productionSource.matchAll(magicPattern)) {
            const name = match[1];
            const ascii = match[2];
            if (name === undefined || ascii === undefined) continue;
            magicBytes.push({
                ascii,
                hex: Buffer.from(ascii, 'ascii').toString('hex'),
                line: sourceLineNumber(source, match.index),
                name,
                path: identity.path,
            });
        }
    }
    const functionalDomains = [...sourcePathsByDomain.entries()]
        .sort(([left], [right]) => left.localeCompare(right, 'en'))
        .map(([domain, sources]) => ({
            domain,
            sources: [...sources].sort((left, right) =>
                left.localeCompare(right, 'en'),
            ),
        }));
    const bySourcePosition = <
        Entry extends { line: number; name: string; path: string },
    >(
        entries: Entry[],
    ): Entry[] =>
        entries.sort(
            (left, right) =>
                left.path.localeCompare(right.path, 'en') ||
                left.line - right.line ||
                left.name.localeCompare(right.name, 'en'),
        );
    return {
        functionalDomains,
        magicBytes: bySourcePosition(magicBytes),
        namedCodes: bySourcePosition(namedCodes),
        enumeratedCodes: bySourcePosition(enumeratedCodes),
    };
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

const writeCandidateSourceClosure = async (
    candidateDirectoryPath: string,
    sourceIdentities: readonly (FileIdentity & Readonly<{ role: string }>)[],
): Promise<readonly Readonly<Record<string, unknown>>[]> => {
    const records: Array<Readonly<Record<string, unknown>>> = [];
    for (const identity of sourceIdentities) {
        const packageRelativePath = `candidate/sources/${identity.path}`;
        const bytes = Uint8Array.from(
            await readFile(path.join(repositoryRoot, identity.path)),
        );
        const destinationPath = path.join(
            candidateDirectoryPath,
            'sources',
            ...identity.path.split('/'),
        );
        await mkdir(path.dirname(destinationPath), { recursive: true });
        await writeFile(destinationPath, bytes, { flag: 'wx' });
        records.push({
            repositoryPath: identity.path,
            role: identity.role,
            packagedSource: identifyBytes(packageRelativePath, bytes),
        });
    }
    return records;
};

const concatenateBytes = (chunks: readonly Uint8Array[]): Uint8Array => {
    const byteLength = chunks.reduce(
        (total, chunk) => total + chunk.byteLength,
        0,
    );
    const bytes = new Uint8Array(byteLength);
    let offset = 0;
    for (const chunk of chunks) {
        bytes.set(chunk, offset);
        offset += chunk.byteLength;
    }
    return bytes;
};

const unsigned16Bytes = (value: number): Uint8Array => {
    const bytes = new Uint8Array(2);
    new DataView(bytes.buffer).setUint16(0, value, true);
    return bytes;
};

const unsigned32Bytes = (value: number): Uint8Array => {
    const bytes = new Uint8Array(4);
    new DataView(bytes.buffer).setUint32(0, value, true);
    return bytes;
};

const encodeIndependentCompilePlanResponse = (topCount: number): Uint8Array => {
    const plan = expectedPlan(topCount) as Readonly<{
        chunks: readonly Readonly<{
            chunkByteLength: number;
            labelEntropyByteLength: number;
            liveWireCountAfterChunk: number;
        }>[];
        constantCount: number;
        conjunctionCount: number;
        inputWireCount: number;
        labelEntropyByteLength: number;
        linearCount: number;
        logicalPayloadByteLength: number;
        manifestByteLength: number;
        maximumLiveWireCount: number;
        negationCount: number;
        operationCount: number;
        optionCount: number;
        outputCount: number;
        participantCount: number;
        topCount: number;
        wireCount: number;
    }>;
    return concatenateBytes([
        Uint8Array.of(0),
        unsigned16Bytes(plan.participantCount),
        unsigned16Bytes(plan.optionCount),
        unsigned16Bytes(plan.topCount),
        ...[
            plan.inputWireCount,
            plan.operationCount,
            plan.constantCount,
            plan.linearCount,
            plan.conjunctionCount,
            plan.negationCount,
            plan.outputCount,
            plan.wireCount,
            plan.logicalPayloadByteLength,
            plan.labelEntropyByteLength,
            plan.manifestByteLength,
            plan.maximumLiveWireCount,
        ].map(unsigned32Bytes),
        unsigned16Bytes(plan.chunks.length),
        ...plan.chunks.flatMap((chunk) => [
            unsigned32Bytes(chunk.chunkByteLength),
            unsigned32Bytes(chunk.labelEntropyByteLength),
            unsigned32Bytes(chunk.liveWireCountAfterChunk),
        ]),
    ]);
};

const decodeRefusalCode = (response: Uint8Array): string => {
    if (response[0] !== 1) {
        throw new Error('A canonical hostile vector did not refuse.');
    }
    let offset = 1;
    const readString = (): string => {
        if (offset + 4 > response.byteLength) {
            throw new Error('A canonical refusal response is truncated.');
        }
        const byteLength = new DataView(
            response.buffer,
            response.byteOffset + offset,
            4,
        ).getUint32(0, true);
        offset += 4;
        const end = offset + byteLength;
        if (end > response.byteLength) {
            throw new Error('A canonical refusal string is truncated.');
        }
        const value = new TextDecoder('utf-8', { fatal: true }).decode(
            response.subarray(offset, end),
        );
        offset = end;
        return value;
    };
    const code = readString();
    readString();
    if (offset !== response.byteLength) {
        throw new Error('A canonical refusal response has trailing bytes.');
    }
    return code;
};

const writeCanonicalConstructionVectors = async (
    candidateDirectoryPath: string,
    candidateKernel: FileIdentity,
): Promise<Readonly<Record<string, unknown>>> => {
    const kernelModule = (await import(
        pathToFileURL(
            path.join(
                repositoryRoot,
                'packages',
                'wasm',
                'dist',
                'foundation-kernel',
                'kernel-runtime.js',
            ),
        ).href
    )) as CandidateKernelModule;
    const kernel =
        await kernelModule.instantiateConstructionKernelCommandRuntime(
            pathToFileURL(
                path.join(
                    repositoryRoot,
                    'packages',
                    'wasm',
                    'dist',
                    'sealed-lattice-kernel.wasm',
                ),
            ),
            { expectedKernelSha256Hex: candidateKernel.sha256Hex },
        );
    const vectorDirectoryPath = path.join(candidateDirectoryPath, 'vectors');
    await mkdir(vectorDirectoryPath, { recursive: true });
    const cases: Array<Readonly<Record<string, unknown>>> = [];
    const writeCase = async (
        name: string,
        request: Uint8Array,
        expected: Readonly<
            | { kind: 'success'; response: Uint8Array }
            | { code: string; kind: 'refusal' }
        >,
    ): Promise<void> => {
        const response = kernel.executeCommand(request);
        if (expected.kind === 'success') {
            if (
                response.byteLength !== expected.response.byteLength ||
                !response.every(
                    (value, index) => value === expected.response[index],
                )
            ) {
                throw new Error(
                    `Canonical vector ${name} differs from the independent response.`,
                );
            }
        } else if (decodeRefusalCode(response) !== expected.code) {
            throw new Error(
                `Canonical vector ${name} returned the wrong refusal code.`,
            );
        }
        const requestRelativePath = `candidate/vectors/${name}.request.bin`;
        const responseRelativePath = `candidate/vectors/${name}.response.bin`;
        await Promise.all([
            writeFile(
                path.join(vectorDirectoryPath, `${name}.request.bin`),
                request,
                { flag: 'wx' },
            ),
            writeFile(
                path.join(vectorDirectoryPath, `${name}.response.bin`),
                response,
                { flag: 'wx' },
            ),
        ]);
        cases.push({
            expectedOutcome:
                expected.kind === 'success'
                    ? { kind: expected.kind }
                    : { code: expected.code, kind: expected.kind },
            name,
            request: identifyBytes(requestRelativePath, request),
            response: identifyBytes(responseRelativePath, response),
        });
    };
    for (let topCount = 1; topCount <= completionOptionCount; topCount += 1) {
        await writeCase(
            `compile-top-count-${String(topCount).padStart(2, '0')}`,
            concatenateBytes([Uint8Array.of(42), unsigned16Bytes(topCount)]),
            {
                kind: 'success',
                response: encodeIndependentCompilePlanResponse(topCount),
            },
        );
    }
    const hostileCases: readonly Readonly<{
        code: string;
        name: string;
        request: Uint8Array;
    }>[] = [
        {
            code: 'MalformedLength',
            name: 'compile-truncated',
            request: Uint8Array.of(42),
        },
        {
            code: 'InvalidProtocolObject',
            name: 'compile-top-count-zero',
            request: Uint8Array.of(42, 0, 0),
        },
        {
            code: 'InvalidProtocolObject',
            name: 'compile-top-count-eleven',
            request: Uint8Array.of(42, 11, 0),
        },
        {
            code: 'TrailingBytes',
            name: 'compile-trailing-byte',
            request: Uint8Array.of(42, 1, 0, 0),
        },
        {
            code: 'InvalidEnum',
            name: 'unsupported-command',
            request: Uint8Array.of(255),
        },
        ...Array.from({ length: 14 }, (_, index) => {
            const command = index + 27;
            return {
                code: 'InvalidProtocolObject',
                name: `tombstoned-command-${String(command)}`,
                request: Uint8Array.of(command),
            };
        }),
    ];
    for (const hostileCase of hostileCases) {
        await writeCase(hostileCase.name, hostileCase.request, {
            code: hostileCase.code,
            kind: 'refusal',
        });
    }
    const manifestBytes = serializeCandidateJson({
        schema: 'sealed-lattice-canonical-construction-vectors',
        schemaVersion: 1,
        cases,
    });
    const manifestRelativePath = 'candidate/vectors/manifest.json';
    await writeFile(
        path.join(vectorDirectoryPath, 'manifest.json'),
        manifestBytes,
        { flag: 'wx' },
    );
    return {
        caseCount: cases.length,
        manifest: identifyBytes(manifestRelativePath, manifestBytes),
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
            path.join(sourcePackagePath, 'README.md'),
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
    const sourceClosure = await writeCandidateSourceClosure(
        candidateDirectoryPath,
        sourceIdentities,
    );
    const protocolGrammar = {
        schema: 'sealed-lattice-candidate-protocol-grammar',
        schemaVersion: 1,
        ...(await extractProtocolGrammar(sourceIdentities)),
        schemaSources: sourceClosure.filter((record) => {
            const repositoryPath = record.repositoryPath;
            return (
                typeof repositoryPath === 'string' &&
                (repositoryPath.startsWith(
                    'crates/sealed-lattice-kernel/src/',
                ) ||
                    repositoryPath.startsWith('packages/wasm/src/'))
            );
        }),
    };
    const protocolGrammarBytes = serializeCandidateJson(protocolGrammar);
    const protocolGrammarRelativePath = 'candidate/protocol-grammar.json';
    await writeFile(
        path.join(candidateDirectoryPath, 'protocol-grammar.json'),
        protocolGrammarBytes,
        { flag: 'wx' },
    );
    const maximumProjection = projectIndependentPaddedTallyWidth(
        compileIndependentPaddedTallyModel(completionOptionCount),
        operationLabelByteLength,
    );
    const parameters = {
        completionProfile: {
            participantCount: completionParticipantCount,
            optionCount: completionOptionCount,
            topCounts: Array.from(
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
        maximumEmittedDemand: {
            maximumChunkByteLength: maximumProjection.maximumChunkByteLength,
            maximumChunkEvaluationRequestByteLength:
                maximumProjection.maximumChunkEvaluationRequestByteLength,
        },
        parserAndAllocationCeilings: {
            maximumCopiedBufferByteLength:
                maximumFoundationCopiedBufferByteLength,
            maximumWasmMemoryByteLength: maximumFoundationWasmMemoryByteLength,
            maximumChunkByteLength: paddedTallyMaximumChunkByteLength,
        },
    };
    const parameterBytes = serializeCandidateJson(parameters);
    const parameterRelativePath = 'candidate/parameters.json';
    await writeFile(
        path.join(candidateDirectoryPath, 'parameters.json'),
        parameterBytes,
        { flag: 'wx' },
    );
    const parameterFiles = [
        { bytes: parameterBytes, path: parameterRelativePath },
        { bytes: protocolGrammarBytes, path: protocolGrammarRelativePath },
    ];
    const parameterIdentityHex = calculateCandidateContentIdentity(
        parameterFiles,
        parameterIdentityDomain,
    );
    const kernelBoundaries = await requireKernelBoundaries();
    const canonicalVectors = await writeCanonicalConstructionVectors(
        candidateDirectoryPath,
        kernelBoundaries.candidateKernel,
    );
    const candidateBundle = {
        schema: 'sealed-lattice-internal-candidate-bundle',
        schemaVersion: 1,
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
                coveredFiles: parameterFiles.map((entry) =>
                    identifyBytes(entry.path, entry.bytes),
                ),
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
        parameterSet: {
            parameters: identifyBytes(parameterRelativePath, parameterBytes),
            protocolGrammar: identifyBytes(
                protocolGrammarRelativePath,
                protocolGrammarBytes,
            ),
        },
        circuits,
        canonicalVectors,
        sourceIdentities: sourceClosure,
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

const parseJsonObject = (
    bytes: Uint8Array,
    description: string,
): Record<string, unknown> => {
    const parsed = JSON.parse(new TextDecoder().decode(bytes)) as unknown;
    if (
        typeof parsed !== 'object' ||
        parsed === null ||
        Array.isArray(parsed)
    ) {
        throw new Error(`${description} is not a JSON object.`);
    }
    return parsed as Record<string, unknown>;
};

const collectObjectKeys = (
    value: unknown,
    output = new Set<string>(),
): Set<string> => {
    if (Array.isArray(value)) {
        for (const entry of value) collectObjectKeys(entry, output);
    } else if (typeof value === 'object' && value !== null) {
        for (const [key, entry] of Object.entries(value)) {
            output.add(key);
            collectObjectKeys(entry, output);
        }
    }
    return output;
};

const requireFileIdentity = (
    rootDirectoryPath: string,
    value: unknown,
    description: string,
): Promise<ContentEntry> => {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        throw new Error(`${description} identity is malformed.`);
    }
    const identity = value as Record<string, unknown>;
    if (
        typeof identity.path !== 'string' ||
        typeof identity.byteLength !== 'number' ||
        typeof identity.sha256Hex !== 'string'
    ) {
        throw new Error(`${description} identity is incomplete.`);
    }
    return readFile(
        path.join(rootDirectoryPath, ...identity.path.split('/')),
    ).then((fileBytes) => {
        const bytes = Uint8Array.from(fileBytes);
        if (
            bytes.byteLength !== identity.byteLength ||
            sha256Hex(bytes) !== identity.sha256Hex
        ) {
            throw new Error(
                `${description} bytes do not match their identity.`,
            );
        }
        return { bytes, path: identity.path as string };
    });
};

const verifyPackedCandidate = async (
    packageDirectoryPath: string,
    consumerDirectoryPath: string,
    tarballPath: string,
    identity: Readonly<{
        candidateBuildIdentityHex: string;
        candidateKernelSha256Hex: string;
        parameterIdentityHex: string;
    }>,
): Promise<void> => {
    const installedPackagePath = path.join(
        consumerDirectoryPath,
        'node_modules',
        '@sealed-lattice',
        'wasm',
    );
    const identityRecord = parseJsonObject(
        Uint8Array.from(
            await readFile(
                path.join(
                    installedPackagePath,
                    ...identityRecordRelativePath.split('/'),
                ),
            ),
        ),
        'Installed candidate identity record',
    );
    if (
        identityRecord.algorithm !== 'SHAKE256-512' ||
        identityRecord.domain !== candidateIdentityDomain ||
        identityRecord.identityHex !== identity.candidateBuildIdentityHex ||
        identityRecord.excludedSelfRecord !== identityRecordRelativePath ||
        !Array.isArray(identityRecord.coveredFiles)
    ) {
        throw new Error('The installed candidate identity record is invalid.');
    }
    const candidateBundle = parseJsonObject(
        Uint8Array.from(
            await readFile(
                path.join(
                    installedPackagePath,
                    'candidate',
                    'candidate-bundle.json',
                ),
            ),
        ),
        'Installed candidate bundle',
    );
    if ('repositoryCommitHash' in candidateBundle) {
        throw new Error(
            'The candidate content identity is coupled to a repository commit.',
        );
    }
    const prohibitedMetadataKey = [...collectObjectKeys(candidateBundle)].find(
        (key) =>
            /^(?:admitted|accepted|selected|ready|security(?:Level|Status)?)$/iu.test(
                key,
            ) || /^(?:admitted|accepted|selected|ready)[A-Z]/u.test(key),
    );
    if (prohibitedMetadataKey !== undefined) {
        throw new Error(
            `The unactivated candidate emits prohibited metadata key ${prohibitedMetadataKey}.`,
        );
    }
    const parameterSet = candidateBundle.parameterSet;
    if (
        typeof parameterSet !== 'object' ||
        parameterSet === null ||
        Array.isArray(parameterSet)
    ) {
        throw new Error('The candidate parameter set is malformed.');
    }
    const parameterSetRecord = parameterSet as Record<string, unknown>;
    const [parameterEntry, grammarEntry] = await Promise.all([
        requireFileIdentity(
            installedPackagePath,
            parameterSetRecord.parameters,
            'Candidate parameters',
        ),
        requireFileIdentity(
            installedPackagePath,
            parameterSetRecord.protocolGrammar,
            'Candidate protocol grammar',
        ),
    ]);
    const recomputedParameterIdentity = calculateCandidateContentIdentity(
        [parameterEntry, grammarEntry],
        parameterIdentityDomain,
    );
    if (recomputedParameterIdentity !== identity.parameterIdentityHex) {
        throw new Error('The installed candidate parameter identity changed.');
    }
    const parameters = parseJsonObject(
        parameterEntry.bytes,
        'Installed candidate parameters',
    );
    const grammar = parseJsonObject(
        grammarEntry.bytes,
        'Installed candidate protocol grammar',
    );
    const parameterText = new TextDecoder().decode(parameterEntry.bytes);
    if (
        parameterText.includes('admittedTopCounts') ||
        !parameterText.includes(
            `"maximumChunkByteLength": ${String(paddedTallyMaximumChunkByteLength)}`,
        )
    ) {
        throw new Error('The candidate parameter boundary is inaccurate.');
    }
    const grammarText = new TextDecoder().decode(grammarEntry.bytes);
    if (
        !grammarText.includes('sealed-lattice.browser-local-inventory.v1') ||
        grammarText.includes('sealed-lattice/proof/transcript/absorb/v1') ||
        !['SLPC', 'SLPM', 'SLPG', 'SLPE', 'SLPR'].every((magic) =>
            grammarText.includes(`"ascii": "${magic}"`),
        ) ||
        !Array.isArray(grammar.schemaSources) ||
        grammar.schemaSources.length === 0 ||
        typeof parameters.completionProfile !== 'object'
    ) {
        throw new Error('The candidate protocol grammar is incomplete.');
    }
    if (!Array.isArray(candidateBundle.sourceIdentities)) {
        throw new Error('The candidate source closure is malformed.');
    }
    for (const source of candidateBundle.sourceIdentities) {
        if (
            typeof source !== 'object' ||
            source === null ||
            Array.isArray(source)
        ) {
            throw new Error('A candidate source-closure row is malformed.');
        }
        const sourceRecord = source as Record<string, unknown>;
        const repositoryPath = sourceRecord.repositoryPath;
        if (
            typeof repositoryPath !== 'string' ||
            repositoryPath.startsWith('packages/wasm/tests/') ||
            (repositoryPath.startsWith('tests/') &&
                repositoryPath !== 'tests/padded-tally-transcript-model.ts') ||
            (repositoryPath.startsWith('tools/ci/') &&
                repositoryPath !==
                    'tools/ci/build-padded-tally-candidate-package.ts' &&
                repositoryPath !== 'tools/ci/build-wasm-kernel.ts')
        ) {
            throw new Error(
                'The candidate source closure includes a non-generator evidence source.',
            );
        }
        await requireFileIdentity(
            installedPackagePath,
            sourceRecord.packagedSource,
            `Candidate source ${repositoryPath}`,
        );
    }
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
    const canonicalVectors = candidateBundle.canonicalVectors;
    if (
        typeof canonicalVectors !== 'object' ||
        canonicalVectors === null ||
        Array.isArray(canonicalVectors)
    ) {
        throw new Error('The candidate canonical vector set is malformed.');
    }
    const canonicalVectorRecord = canonicalVectors as Record<string, unknown>;
    const vectorManifestEntry = await requireFileIdentity(
        installedPackagePath,
        canonicalVectorRecord.manifest,
        'Canonical vector manifest',
    );
    const vectorManifest = parseJsonObject(
        vectorManifestEntry.bytes,
        'Canonical vector manifest',
    );
    if (!Array.isArray(vectorManifest.cases)) {
        throw new Error('The canonical vector manifest omits its cases.');
    }
    for (const [index, vector] of vectorManifest.cases.entries()) {
        if (
            typeof vector !== 'object' ||
            vector === null ||
            Array.isArray(vector)
        ) {
            throw new Error(`Canonical vector ${String(index)} is malformed.`);
        }
        const vectorRecord = vector as Record<string, unknown>;
        const [requestEntry, responseEntry] = await Promise.all([
            requireFileIdentity(
                installedPackagePath,
                vectorRecord.request,
                `Canonical vector ${String(index)} request`,
            ),
            requireFileIdentity(
                installedPackagePath,
                vectorRecord.response,
                `Canonical vector ${String(index)} response`,
            ),
        ]);
        const response = kernel.executeCommand(requestEntry.bytes);
        if (
            response.byteLength !== responseEntry.bytes.byteLength ||
            !response.every(
                (value, responseIndex) =>
                    value === responseEntry.bytes[responseIndex],
            )
        ) {
            throw new Error(
                `Canonical vector ${String(index)} does not replay byte-identically.`,
            );
        }
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
    requireExactValue(
        identityRecord.coveredFiles,
        installedEntries.map((entry) => identifyBytes(entry.path, entry.bytes)),
        'Installed candidate covered-file inventory',
    );
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

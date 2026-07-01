import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { readFile, stat } from 'node:fs/promises';
import {
    createServer,
    type IncomingMessage,
    type ServerResponse,
} from 'node:http';
import { networkInterfaces } from 'node:os';
import { basename, dirname, extname, resolve, sep, relative } from 'node:path';
import { performance } from 'node:perf_hooks';
import { fileURLToPath, pathToFileURL } from 'node:url';

type JsonRecord = Record<string, unknown>;

type RuntimeEvidenceMode = 'browser' | 'node-diagnostic' | 'contract-template';

type RuntimeContract = Readonly<{
    objectType: 'SupportedRuntimeEvidenceContract';
    objectVersion: 1;
    evidenceScope: string;
    runtime: Readonly<{
        deviceClass: string;
        deviceModel: string;
        operatingSystem: string;
        browserOrEngine: string;
        browserOrEngineVersion: string;
        throttlingPolicy: string;
        batteryPolicy: string;
        repeatCount: number;
    }>;
    budgets: Readonly<{
        maximumSetupVerificationMilliseconds: number;
        maximumTargetResultReleaseMilliseconds: number;
        maximumSetupInputJsonBytes: number;
        maximumTargetResultInputJsonBytes: number;
        maximumResultJsonBytes: number;
        maximumJsHeapUsedBytes: number;
    }>;
    expected: Readonly<{
        setupVerifierStatus: string;
        targetResultHash: string;
        targetShareEvidenceCount: number;
    }>;
}>;

type ParsedArguments = Readonly<{
    mode: RuntimeEvidenceMode;
    contractPath: string | undefined;
    setupInputPath: string | undefined;
    targetResultInputPath: string | undefined;
    host: string;
    port: number;
}>;

type LoadedJsonFile = Readonly<{
    path: string;
    jsonText: string;
    jsonByteLength: number;
    value: unknown;
    sha256Hex: string;
}>;

type LoadedEvidenceInputs = Readonly<{
    contract: RuntimeContract;
    contractFile: LoadedJsonFile;
    setupInputFile: LoadedJsonFile;
    targetResultInputFile: LoadedJsonFile;
}>;

type TimedMeasurement = Readonly<{
    name: string;
    milliseconds: number;
    resultJsonBytes: number;
    result: JsonRecord;
}>;

type NodeDiagnosticReport = Readonly<{
    objectType: 'SupportedRuntimeNodeDiagnosticReport';
    objectVersion: 1;
    evidenceScope: string;
    contract: RuntimeContract;
    inputs: Readonly<{
        contractPath: string;
        setupInputPath: string;
        targetResultInputPath: string;
        contractSha256Hex: string;
        setupInputSha256Hex: string;
        targetResultInputSha256Hex: string;
        setupInputJsonBytes: number;
        targetResultInputJsonBytes: number;
    }>;
    packageEntryPoint: string;
    packageArtifactSha256Hex: string;
    measurements: readonly TimedMeasurement[];
    budgetFindings: readonly JsonRecord[];
}>;

const repositoryRoot = resolve(
    dirname(fileURLToPath(import.meta.url)),
    '../..',
);
const publicPackageRoot = resolve(repositoryRoot, 'packages/sdk/dist');
const publicPackageEntryPoint = resolve(publicPackageRoot, 'index.js');
const defaultHost = '127.0.0.1';
const defaultPort = 4175;
const textEncoder = new TextEncoder();

const usage = (): string => `Usage:
  pnpm run measure:compact-vss:supported-runtime -- --mode contract-template
  pnpm run measure:compact-vss:supported-runtime -- --mode node-diagnostic --contract <contract.json> --setup-input <setup-input.json> --target-result-input <target-input.json>
  pnpm run measure:compact-vss:supported-runtime -- --mode browser --contract <contract.json> --setup-input <setup-input.json> --target-result-input <target-input.json> [--host 127.0.0.1] [--port 4175]

The browser mode serves the built public SDK package and the two input JSON
files. Use --host 0.0.0.0 only when the supported device must connect over the
local network, because the input files become reachable to that network while
the server is running.`;

const contractTemplate = (): RuntimeContract => ({
    objectType: 'SupportedRuntimeEvidenceContract',
    objectVersion: 1,
    evidenceScope:
        'Manual supported-runtime evidence for public setup verification and proof-backed target-result release through the published SDK package boundary.',
    runtime: {
        deviceClass: 'physical phone',
        deviceModel: 'replace with exact model',
        operatingSystem: 'replace with exact operating-system version',
        browserOrEngine: 'replace with browser or engine',
        browserOrEngineVersion: 'replace with exact browser or engine version',
        throttlingPolicy: 'replace with thermal and throttling policy',
        batteryPolicy: 'replace with battery or power policy',
        repeatCount: 1,
    },
    budgets: {
        maximumSetupVerificationMilliseconds: 30_000,
        maximumTargetResultReleaseMilliseconds: 30_000,
        maximumSetupInputJsonBytes: 67_108_864,
        maximumTargetResultInputJsonBytes: 48_000_000,
        maximumResultJsonBytes: 1_048_576,
        maximumJsHeapUsedBytes: 1_500_000_000,
    },
    expected: {
        setupVerifierStatus: 'accepted',
        targetResultHash: 'replace with expected targetResultHash',
        targetShareEvidenceCount: 2,
    },
});

const parseArguments = (argv: readonly string[]): ParsedArguments => {
    let mode: RuntimeEvidenceMode | undefined;
    let contractPath: string | undefined;
    let setupInputPath: string | undefined;
    let targetResultInputPath: string | undefined;
    let host = defaultHost;
    let port = defaultPort;

    for (
        let argumentIndex = 0;
        argumentIndex < argv.length;
        argumentIndex += 1
    ) {
        const argument = argv[argumentIndex];
        const nextValue = (): string => {
            const value = argv[argumentIndex + 1];
            if (value === undefined || value.startsWith('--')) {
                throw new Error(`${argument} expects a value.`);
            }
            argumentIndex += 1;

            return value;
        };

        switch (argument) {
            case '--mode': {
                const value = nextValue();
                if (
                    value !== 'browser' &&
                    value !== 'node-diagnostic' &&
                    value !== 'contract-template'
                ) {
                    throw new Error(
                        '--mode must be browser, node-diagnostic, or contract-template.',
                    );
                }
                mode = value;
                break;
            }
            case '--contract':
                contractPath = nextValue();
                break;
            case '--setup-input':
                setupInputPath = nextValue();
                break;
            case '--target-result-input':
                targetResultInputPath = nextValue();
                break;
            case '--host':
                host = nextValue();
                break;
            case '--port': {
                const parsedPort = Number.parseInt(nextValue(), 10);
                if (
                    !Number.isSafeInteger(parsedPort) ||
                    parsedPort < 0 ||
                    parsedPort > 65_535
                ) {
                    throw new Error(
                        '--port must be an integer from 0 to 65535.',
                    );
                }
                port = parsedPort;
                break;
            }
            case '--help':
                console.log(usage());
                process.exitCode = 0;
                return {
                    mode: 'contract-template',
                    contractPath,
                    setupInputPath,
                    targetResultInputPath,
                    host,
                    port,
                };
            default:
                throw new Error(`Unknown argument: ${argument}`);
        }
    }

    return {
        mode: mode ?? 'browser',
        contractPath,
        setupInputPath,
        targetResultInputPath,
        host,
        port,
    };
};

const requireRecord = (value: unknown, fieldName: string): JsonRecord => {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        throw new TypeError(`${fieldName} must be an object.`);
    }

    return value as JsonRecord;
};

const requireString = (value: unknown, fieldName: string): string => {
    if (typeof value !== 'string' || value.length === 0) {
        throw new TypeError(`${fieldName} must be a non-empty string.`);
    }

    return value;
};

const requirePositiveNumber = (value: unknown, fieldName: string): number => {
    if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) {
        throw new TypeError(`${fieldName} must be a positive number.`);
    }

    return value;
};

const requirePositiveInteger = (value: unknown, fieldName: string): number => {
    if (!Number.isSafeInteger(value) || (value as number) <= 0) {
        throw new TypeError(`${fieldName} must be a positive integer.`);
    }

    return value as number;
};

const parseContract = (value: unknown): RuntimeContract => {
    const contract = requireRecord(value, 'contract');
    if (contract.objectType !== 'SupportedRuntimeEvidenceContract') {
        throw new TypeError(
            'contract.objectType must be SupportedRuntimeEvidenceContract.',
        );
    }
    if (contract.objectVersion !== 1) {
        throw new TypeError('contract.objectVersion must be 1.');
    }

    const runtime = requireRecord(contract.runtime, 'contract.runtime');
    const budgets = requireRecord(contract.budgets, 'contract.budgets');
    const expected = requireRecord(contract.expected, 'contract.expected');

    return {
        objectType: 'SupportedRuntimeEvidenceContract',
        objectVersion: 1,
        evidenceScope: requireString(
            contract.evidenceScope,
            'contract.evidenceScope',
        ),
        runtime: {
            deviceClass: requireString(
                runtime.deviceClass,
                'contract.runtime.deviceClass',
            ),
            deviceModel: requireString(
                runtime.deviceModel,
                'contract.runtime.deviceModel',
            ),
            operatingSystem: requireString(
                runtime.operatingSystem,
                'contract.runtime.operatingSystem',
            ),
            browserOrEngine: requireString(
                runtime.browserOrEngine,
                'contract.runtime.browserOrEngine',
            ),
            browserOrEngineVersion: requireString(
                runtime.browserOrEngineVersion,
                'contract.runtime.browserOrEngineVersion',
            ),
            throttlingPolicy: requireString(
                runtime.throttlingPolicy,
                'contract.runtime.throttlingPolicy',
            ),
            batteryPolicy: requireString(
                runtime.batteryPolicy,
                'contract.runtime.batteryPolicy',
            ),
            repeatCount: requirePositiveInteger(
                runtime.repeatCount,
                'contract.runtime.repeatCount',
            ),
        },
        budgets: {
            maximumSetupVerificationMilliseconds: requirePositiveNumber(
                budgets.maximumSetupVerificationMilliseconds,
                'contract.budgets.maximumSetupVerificationMilliseconds',
            ),
            maximumTargetResultReleaseMilliseconds: requirePositiveNumber(
                budgets.maximumTargetResultReleaseMilliseconds,
                'contract.budgets.maximumTargetResultReleaseMilliseconds',
            ),
            maximumSetupInputJsonBytes: requirePositiveInteger(
                budgets.maximumSetupInputJsonBytes,
                'contract.budgets.maximumSetupInputJsonBytes',
            ),
            maximumTargetResultInputJsonBytes: requirePositiveInteger(
                budgets.maximumTargetResultInputJsonBytes,
                'contract.budgets.maximumTargetResultInputJsonBytes',
            ),
            maximumResultJsonBytes: requirePositiveInteger(
                budgets.maximumResultJsonBytes,
                'contract.budgets.maximumResultJsonBytes',
            ),
            maximumJsHeapUsedBytes: requirePositiveInteger(
                budgets.maximumJsHeapUsedBytes,
                'contract.budgets.maximumJsHeapUsedBytes',
            ),
        },
        expected: {
            setupVerifierStatus: requireString(
                expected.setupVerifierStatus,
                'contract.expected.setupVerifierStatus',
            ),
            targetResultHash: requireString(
                expected.targetResultHash,
                'contract.expected.targetResultHash',
            ),
            targetShareEvidenceCount: requirePositiveInteger(
                expected.targetShareEvidenceCount,
                'contract.expected.targetShareEvidenceCount',
            ),
        },
    };
};

const sha256Hex = (bytes: string | Uint8Array): string =>
    createHash('sha256').update(bytes).digest('hex');

const readJsonFile = async (filePath: string): Promise<LoadedJsonFile> => {
    const resolvedPath = resolve(filePath);
    const jsonText = await readFile(resolvedPath, 'utf8');

    return {
        path: resolvedPath,
        jsonText,
        jsonByteLength: textEncoder.encode(jsonText).byteLength,
        value: JSON.parse(jsonText) as unknown,
        sha256Hex: sha256Hex(jsonText),
    };
};

const requireInputPaths = (
    parsedArguments: ParsedArguments,
): Readonly<{
    readonly contractPath: string;
    readonly setupInputPath: string;
    readonly targetResultInputPath: string;
}> => {
    if (
        parsedArguments.contractPath === undefined ||
        parsedArguments.setupInputPath === undefined ||
        parsedArguments.targetResultInputPath === undefined
    ) {
        throw new Error(
            'The selected mode requires --contract, --setup-input, and --target-result-input.',
        );
    }

    return {
        contractPath: parsedArguments.contractPath,
        setupInputPath: parsedArguments.setupInputPath,
        targetResultInputPath: parsedArguments.targetResultInputPath,
    };
};

const loadEvidenceInputs = async (
    parsedArguments: ParsedArguments,
): Promise<LoadedEvidenceInputs> => {
    const inputPaths = requireInputPaths(parsedArguments);
    const [contractFile, setupInputFile, targetResultInputFile] =
        await Promise.all([
            readJsonFile(inputPaths.contractPath),
            readJsonFile(inputPaths.setupInputPath),
            readJsonFile(inputPaths.targetResultInputPath),
        ]);
    const contract = parseContract(contractFile.value);

    if (
        setupInputFile.jsonByteLength >
        contract.budgets.maximumSetupInputJsonBytes
    ) {
        throw new Error(
            `setup input JSON exceeds the contract budget: ${String(setupInputFile.jsonByteLength)} > ${String(contract.budgets.maximumSetupInputJsonBytes)}.`,
        );
    }
    if (
        targetResultInputFile.jsonByteLength >
        contract.budgets.maximumTargetResultInputJsonBytes
    ) {
        throw new Error(
            `target-result input JSON exceeds the contract budget: ${String(targetResultInputFile.jsonByteLength)} > ${String(contract.budgets.maximumTargetResultInputJsonBytes)}.`,
        );
    }

    return {
        contract,
        contractFile,
        setupInputFile,
        targetResultInputFile,
    };
};

const packageArtifactHash = async (): Promise<string> => {
    const entryPointBytes = await readFile(publicPackageEntryPoint);

    return sha256Hex(entryPointBytes);
};

const requireBuiltPublicPackage = async (): Promise<void> => {
    try {
        await stat(publicPackageEntryPoint);
        await stat(resolve(publicPackageRoot, 'sealed-lattice-kernel.wasm'));
    } catch {
        throw new Error(
            'Build the public SDK package before measuring: pnpm --filter sealed-lattice run build',
        );
    }
};

const jsonByteLength = (value: unknown): number =>
    textEncoder.encode(JSON.stringify(value)).byteLength;

const measureCall = async (
    name: string,
    call: () => Promise<unknown>,
): Promise<TimedMeasurement> => {
    const startedAtMilliseconds = performance.now();
    const result = await call();
    const milliseconds = performance.now() - startedAtMilliseconds;

    return {
        name,
        milliseconds,
        resultJsonBytes: jsonByteLength(result),
        result: requireRecord(result, `${name} result`),
    };
};

const buildBudgetFindings = (
    contract: RuntimeContract,
    setupMeasurements: readonly TimedMeasurement[],
    targetMeasurements: readonly TimedMeasurement[],
): readonly JsonRecord[] => {
    const maximumSetupMilliseconds = Math.max(
        ...setupMeasurements.map((measurement) => measurement.milliseconds),
    );
    const maximumTargetMilliseconds = Math.max(
        ...targetMeasurements.map((measurement) => measurement.milliseconds),
    );
    const maximumResultJsonBytes = Math.max(
        ...setupMeasurements.map((measurement) => measurement.resultJsonBytes),
        ...targetMeasurements.map((measurement) => measurement.resultJsonBytes),
    );

    return [
        {
            criterion: 'setup verification maximum milliseconds',
            measuredValue: maximumSetupMilliseconds,
            budgetValue: contract.budgets.maximumSetupVerificationMilliseconds,
            outcome:
                maximumSetupMilliseconds <=
                contract.budgets.maximumSetupVerificationMilliseconds
                    ? 'within budget'
                    : 'exceeds budget',
        },
        {
            criterion: 'target-result release maximum milliseconds',
            measuredValue: maximumTargetMilliseconds,
            budgetValue:
                contract.budgets.maximumTargetResultReleaseMilliseconds,
            outcome:
                maximumTargetMilliseconds <=
                contract.budgets.maximumTargetResultReleaseMilliseconds
                    ? 'within budget'
                    : 'exceeds budget',
        },
        {
            criterion: 'result JSON bytes',
            measuredValue: maximumResultJsonBytes,
            budgetValue: contract.budgets.maximumResultJsonBytes,
            outcome:
                maximumResultJsonBytes <=
                contract.budgets.maximumResultJsonBytes
                    ? 'within budget'
                    : 'exceeds budget',
        },
    ];
};

const assertExpectedResults = (
    contract: RuntimeContract,
    setupMeasurements: readonly TimedMeasurement[],
    targetMeasurements: readonly TimedMeasurement[],
): void => {
    for (const measurement of setupMeasurements) {
        if (
            measurement.result.verifierStatus !==
            contract.expected.setupVerifierStatus
        ) {
            throw new Error(
                `setup verification returned verifierStatus ${String(measurement.result.verifierStatus)}, expected ${contract.expected.setupVerifierStatus}.`,
            );
        }
    }
    for (const measurement of targetMeasurements) {
        const acceptedResult = requireRecord(
            measurement.result.acceptedResult,
            'target-result acceptedResult',
        );
        const targetResultHash = requireString(
            acceptedResult.targetResultHash,
            'target-result acceptedResult.targetResultHash',
        );
        if (targetResultHash !== contract.expected.targetResultHash) {
            throw new Error(
                `target-result hash ${targetResultHash} does not match expected ${contract.expected.targetResultHash}.`,
            );
        }
        const shareEvidence = Array.isArray(acceptedResult.shareEvidence)
            ? acceptedResult.shareEvidence
            : undefined;
        if (
            shareEvidence?.length !== contract.expected.targetShareEvidenceCount
        ) {
            throw new Error(
                `target-result shareEvidence length does not match expected ${String(contract.expected.targetShareEvidenceCount)}.`,
            );
        }
    }
};

const runNodeDiagnostic = async (
    loadedInputs: LoadedEvidenceInputs,
): Promise<NodeDiagnosticReport> => {
    await requireBuiltPublicPackage();
    const publicPackage = (await import(
        pathToFileURL(publicPackageEntryPoint).href
    )) as JsonRecord;
    const verifySetupPackage = publicPackage.verifySetupPackage;
    const verifyTargetDecryptionResult =
        publicPackage.verifyTargetDecryptionResult;
    if (typeof verifySetupPackage !== 'function') {
        throw new Error(
            'Built public package does not export verifySetupPackage.',
        );
    }
    if (typeof verifyTargetDecryptionResult !== 'function') {
        throw new Error(
            'Built public package does not export verifyTargetDecryptionResult.',
        );
    }

    const setupMeasurements: TimedMeasurement[] = [];
    const targetMeasurements: TimedMeasurement[] = [];
    for (
        let repetitionIndex = 0;
        repetitionIndex < loadedInputs.contract.runtime.repeatCount;
        repetitionIndex += 1
    ) {
        setupMeasurements.push(
            await measureCall('verifySetupPackage', () =>
                (verifySetupPackage as (input: unknown) => Promise<unknown>)(
                    loadedInputs.setupInputFile.value,
                ),
            ),
        );
        targetMeasurements.push(
            await measureCall('verifyTargetDecryptionResult', () =>
                (
                    verifyTargetDecryptionResult as (
                        input: unknown,
                    ) => Promise<unknown>
                )(loadedInputs.targetResultInputFile.value),
            ),
        );
    }
    assertExpectedResults(
        loadedInputs.contract,
        setupMeasurements,
        targetMeasurements,
    );

    return {
        objectType: 'SupportedRuntimeNodeDiagnosticReport',
        objectVersion: 1,
        evidenceScope:
            'Node public-package replay diagnostic only; this is not supported-runtime evidence.',
        contract: loadedInputs.contract,
        inputs: {
            contractPath: loadedInputs.contractFile.path,
            setupInputPath: loadedInputs.setupInputFile.path,
            targetResultInputPath: loadedInputs.targetResultInputFile.path,
            contractSha256Hex: loadedInputs.contractFile.sha256Hex,
            setupInputSha256Hex: loadedInputs.setupInputFile.sha256Hex,
            targetResultInputSha256Hex:
                loadedInputs.targetResultInputFile.sha256Hex,
            setupInputJsonBytes: loadedInputs.setupInputFile.jsonByteLength,
            targetResultInputJsonBytes:
                loadedInputs.targetResultInputFile.jsonByteLength,
        },
        packageEntryPoint: publicPackageEntryPoint,
        packageArtifactSha256Hex: await packageArtifactHash(),
        measurements: [...setupMeasurements, ...targetMeasurements],
        budgetFindings: buildBudgetFindings(
            loadedInputs.contract,
            setupMeasurements,
            targetMeasurements,
        ),
    };
};

const contentTypeForPath = (filePath: string): string => {
    switch (extname(filePath)) {
        case '.js':
            return 'text/javascript; charset=utf-8';
        case '.wasm':
            return 'application/wasm';
        case '.json':
            return 'application/json; charset=utf-8';
        case '.html':
            return 'text/html; charset=utf-8';
        case '.css':
            return 'text/css; charset=utf-8';
        default:
            return 'application/octet-stream';
    }
};

const sendText = (
    response: ServerResponse,
    statusCode: number,
    contentType: string,
    body: string,
): void => {
    response.writeHead(statusCode, {
        'content-type': contentType,
        'cache-control': 'no-store',
    });
    response.end(body);
};

const safePackagePath = (requestPath: string): string => {
    const withoutPrefix = requestPath.replace(/^\/sdk\//u, '');
    const decodedPath = decodeURIComponent(withoutPrefix);
    const resolvedPath = resolve(publicPackageRoot, decodedPath);
    const relativePath = relative(publicPackageRoot, resolvedPath);
    if (
        relativePath.startsWith(`..${sep}`) ||
        relativePath === '..' ||
        relativePath.startsWith('..')
    ) {
        throw new Error('Requested SDK path escapes the public package root.');
    }

    return resolvedPath;
};

const streamFile = async (
    response: ServerResponse,
    filePath: string,
): Promise<void> => {
    await stat(filePath);
    response.writeHead(200, {
        'content-type': contentTypeForPath(filePath),
        'cache-control': 'no-store',
    });
    createReadStream(filePath).pipe(response);
};

const browserHarnessHtml = (): string => `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>sealed-lattice supported-runtime evidence</title>
  <style>
    :root {
      color-scheme: light dark;
      font-family: system-ui, sans-serif;
      line-height: 1.4;
    }
    body {
      margin: 0;
      padding: 24px;
      max-width: 960px;
    }
    h1 {
      font-size: 1.35rem;
      margin: 0 0 16px;
    }
    button {
      font: inherit;
      padding: 8px 12px;
    }
    pre {
      overflow: auto;
      white-space: pre-wrap;
      border: 1px solid currentColor;
      padding: 12px;
    }
  </style>
</head>
<body>
  <h1>sealed-lattice supported-runtime evidence</h1>
  <button id="run-button" type="button">Run measurement</button>
  <pre id="output">Waiting.</pre>
  <script type="module">
    import { verifySetupPackage, verifyTargetDecryptionResult } from '/sdk/index.js';

    const output = document.querySelector('#output');
    const runButton = document.querySelector('#run-button');
    const textEncoder = new TextEncoder();

    const jsonByteLength = (value) => textEncoder.encode(JSON.stringify(value)).byteLength;
    const readJson = async (url) => {
      const response = await fetch(url, { cache: 'no-store' });
      if (!response.ok) {
        throw new Error(\`Failed to load \${url}: \${response.status}\`);
      }
      const text = await response.text();
      return {
        text,
        jsonByteLength: textEncoder.encode(text).byteLength,
        value: JSON.parse(text),
      };
    };
    const heapSnapshot = () => {
      const memory = performance.memory;
      if (memory === undefined) {
        return {
          measurement: 'not available in this browser',
        };
      }
      return {
        usedJSHeapSize: memory.usedJSHeapSize,
        totalJSHeapSize: memory.totalJSHeapSize,
        jsHeapSizeLimit: memory.jsHeapSizeLimit,
      };
    };
    const measureCall = async (name, call) => {
      const heapBefore = heapSnapshot();
      const startedAtMilliseconds = performance.now();
      const result = await call();
      const milliseconds = performance.now() - startedAtMilliseconds;
      const heapAfter = heapSnapshot();

      return {
        name,
        milliseconds,
        resultJsonBytes: jsonByteLength(result),
        heapBefore,
        heapAfter,
        result,
      };
    };
    const assertResult = (condition, message) => {
      if (!condition) {
        throw new Error(message);
      }
    };
    const buildBudgetFindings = (contract, setupMeasurements, targetMeasurements) => {
      const maximumSetupMilliseconds = Math.max(
        ...setupMeasurements.map((measurement) => measurement.milliseconds),
      );
      const maximumTargetMilliseconds = Math.max(
        ...targetMeasurements.map((measurement) => measurement.milliseconds),
      );
      const maximumResultJsonBytes = Math.max(
        ...setupMeasurements.map((measurement) => measurement.resultJsonBytes),
        ...targetMeasurements.map((measurement) => measurement.resultJsonBytes),
      );
      const jsHeapValues = [...setupMeasurements, ...targetMeasurements]
        .flatMap((measurement) => [
          measurement.heapBefore.usedJSHeapSize,
          measurement.heapAfter.usedJSHeapSize,
        ])
        .filter((value) => typeof value === 'number');
      const maximumJsHeapUsedBytes =
        jsHeapValues.length === 0 ? undefined : Math.max(...jsHeapValues);
      const findings = [
        {
          criterion: 'setup verification maximum milliseconds',
          measuredValue: maximumSetupMilliseconds,
          budgetValue: contract.budgets.maximumSetupVerificationMilliseconds,
          outcome:
            maximumSetupMilliseconds <= contract.budgets.maximumSetupVerificationMilliseconds
              ? 'within budget'
              : 'exceeds budget',
        },
        {
          criterion: 'target-result release maximum milliseconds',
          measuredValue: maximumTargetMilliseconds,
          budgetValue: contract.budgets.maximumTargetResultReleaseMilliseconds,
          outcome:
            maximumTargetMilliseconds <= contract.budgets.maximumTargetResultReleaseMilliseconds
              ? 'within budget'
              : 'exceeds budget',
        },
        {
          criterion: 'result JSON bytes',
          measuredValue: maximumResultJsonBytes,
          budgetValue: contract.budgets.maximumResultJsonBytes,
          outcome:
            maximumResultJsonBytes <= contract.budgets.maximumResultJsonBytes
              ? 'within budget'
              : 'exceeds budget',
        },
      ];
      if (maximumJsHeapUsedBytes !== undefined) {
        findings.push({
          criterion: 'JS heap used bytes',
          measuredValue: maximumJsHeapUsedBytes,
          budgetValue: contract.budgets.maximumJsHeapUsedBytes,
          outcome:
            maximumJsHeapUsedBytes <= contract.budgets.maximumJsHeapUsedBytes
              ? 'within budget'
              : 'exceeds budget',
        });
      }
      return findings;
    };
    const runMeasurement = async () => {
      runButton.disabled = true;
      output.textContent = 'Loading inputs.';
      const [contractFile, setupInputFile, targetResultInputFile, packageManifest] =
        await Promise.all([
          readJson('/contract.json'),
          readJson('/setup-input.json'),
          readJson('/target-result-input.json'),
          readJson('/package-manifest.json'),
        ]);
      const contract = contractFile.value;
      assertResult(
        setupInputFile.jsonByteLength <= contract.budgets.maximumSetupInputJsonBytes,
        'setup input JSON exceeds the contract budget',
      );
      assertResult(
        targetResultInputFile.jsonByteLength <=
          contract.budgets.maximumTargetResultInputJsonBytes,
        'target-result input JSON exceeds the contract budget',
      );

      output.textContent = 'Running public package calls.';
      const setupMeasurements = [];
      const targetMeasurements = [];
      for (let repetitionIndex = 0; repetitionIndex < contract.runtime.repeatCount; repetitionIndex += 1) {
        setupMeasurements.push(
          await measureCall('verifySetupPackage', () =>
            verifySetupPackage(setupInputFile.value),
          ),
        );
        targetMeasurements.push(
          await measureCall('verifyTargetDecryptionResult', () =>
            verifyTargetDecryptionResult(targetResultInputFile.value),
          ),
        );
      }
      for (const measurement of setupMeasurements) {
        assertResult(
          measurement.result.verifierStatus === contract.expected.setupVerifierStatus,
          \`setup verifierStatus was \${measurement.result.verifierStatus}, expected \${contract.expected.setupVerifierStatus}\`,
        );
      }
      for (const measurement of targetMeasurements) {
        assertResult(
          measurement.result.acceptedResult?.targetResultHash ===
            contract.expected.targetResultHash,
          'target-result hash did not match the expected hash',
        );
        assertResult(
          measurement.result.acceptedResult?.shareEvidence?.length ===
            contract.expected.targetShareEvidenceCount,
          'target-result share evidence count did not match the expected count',
        );
      }
      const report = {
        objectType: 'SupportedRuntimeBrowserEvidenceReport',
        objectVersion: 1,
        evidenceScope: contract.evidenceScope,
        browserUserAgent: navigator.userAgent,
        browserLanguage: navigator.language,
        measuredAtIso: new Date().toISOString(),
        contract,
        inputs: {
          setupInputJsonBytes: setupInputFile.jsonByteLength,
          targetResultInputJsonBytes: targetResultInputFile.jsonByteLength,
        },
        packageManifest,
        setupMeasurements,
        targetMeasurements,
        budgetFindings: buildBudgetFindings(
          contract,
          setupMeasurements,
          targetMeasurements,
        ),
      };
      output.textContent = JSON.stringify(report, null, 2);
      const reportBlob = new Blob([JSON.stringify(report, null, 2)], {
        type: 'application/json',
      });
      const reportUrl = URL.createObjectURL(reportBlob);
      const link = document.createElement('a');
      link.href = reportUrl;
      link.download = 'supported-runtime-evidence-report.json';
      link.textContent = 'Download report';
      document.body.appendChild(link);
    };

    runButton.addEventListener('click', () => {
      runMeasurement().catch((error) => {
        output.textContent = String(error?.stack ?? error);
        runButton.disabled = false;
      });
    });
  </script>
</body>
</html>
`;

const localNetworkUrls = (port: number): readonly string[] =>
    Object.values(networkInterfaces())
        .flatMap((networkInterface) => networkInterface ?? [])
        .filter(
            (address) =>
                address.family === 'IPv4' && !address.internal && port > 0,
        )
        .map((address) => `http://${address.address}:${String(port)}/`);

const startBrowserHarness = async (
    parsedArguments: ParsedArguments,
    loadedInputs: LoadedEvidenceInputs,
): Promise<void> => {
    await requireBuiltPublicPackage();
    const packageManifest = {
        packageEntryPoint: '/sdk/index.js',
        packageArtifactSha256Hex: await packageArtifactHash(),
        packageArtifactSource: publicPackageEntryPoint,
        setupInputSource: basename(loadedInputs.setupInputFile.path),
        targetResultInputSource: basename(
            loadedInputs.targetResultInputFile.path,
        ),
    };

    const server = createServer(
        (request: IncomingMessage, response: ServerResponse) => {
            void (async (): Promise<void> => {
                const requestUrl = new URL(
                    request.url ?? '/',
                    `http://${parsedArguments.host}:${String(parsedArguments.port)}`,
                );
                if (requestUrl.pathname === '/') {
                    sendText(
                        response,
                        200,
                        'text/html; charset=utf-8',
                        browserHarnessHtml(),
                    );
                    return;
                }
                if (requestUrl.pathname === '/contract.json') {
                    sendText(
                        response,
                        200,
                        'application/json; charset=utf-8',
                        JSON.stringify(loadedInputs.contract, null, 2),
                    );
                    return;
                }
                if (requestUrl.pathname === '/setup-input.json') {
                    sendText(
                        response,
                        200,
                        'application/json; charset=utf-8',
                        loadedInputs.setupInputFile.jsonText,
                    );
                    return;
                }
                if (requestUrl.pathname === '/target-result-input.json') {
                    sendText(
                        response,
                        200,
                        'application/json; charset=utf-8',
                        loadedInputs.targetResultInputFile.jsonText,
                    );
                    return;
                }
                if (requestUrl.pathname === '/package-manifest.json') {
                    sendText(
                        response,
                        200,
                        'application/json; charset=utf-8',
                        JSON.stringify(packageManifest, null, 2),
                    );
                    return;
                }
                if (requestUrl.pathname.startsWith('/sdk/')) {
                    await streamFile(
                        response,
                        safePackagePath(requestUrl.pathname),
                    );
                    return;
                }
                sendText(
                    response,
                    404,
                    'text/plain; charset=utf-8',
                    'Not found.',
                );
            })().catch((error: unknown) => {
                sendText(
                    response,
                    500,
                    'text/plain; charset=utf-8',
                    String(error instanceof Error ? error.message : error),
                );
            });
        },
    );

    await new Promise<void>((resolvePromise, rejectPromise) => {
        server.once('error', rejectPromise);
        server.listen(parsedArguments.port, parsedArguments.host, () => {
            server.off('error', rejectPromise);
            resolvePromise();
        });
    });
    const address = server.address();
    const boundPort =
        typeof address === 'object' && address !== null
            ? address.port
            : parsedArguments.port;
    console.log(
        JSON.stringify(
            {
                objectType: 'SupportedRuntimeEvidenceServer',
                objectVersion: 1,
                localUrl: `http://${parsedArguments.host}:${String(boundPort)}/`,
                localNetworkUrls: localNetworkUrls(boundPort),
                packageEntryPoint: publicPackageEntryPoint,
                setupInputPath: loadedInputs.setupInputFile.path,
                targetResultInputPath: loadedInputs.targetResultInputFile.path,
                evidenceScope: loadedInputs.contract.evidenceScope,
            },
            null,
            2,
        ),
    );
};

const main = async (): Promise<void> => {
    const parsedArguments = parseArguments(process.argv.slice(2));
    if (process.exitCode === 0) {
        return;
    }
    if (parsedArguments.mode === 'contract-template') {
        console.log(JSON.stringify(contractTemplate(), null, 2));
        return;
    }

    const loadedInputs = await loadEvidenceInputs(parsedArguments);
    if (parsedArguments.mode === 'node-diagnostic') {
        const report = await runNodeDiagnostic(loadedInputs);
        console.log(JSON.stringify(report, null, 2));
        return;
    }

    await startBrowserHarness(parsedArguments, loadedInputs);
};

main().catch((error: unknown) => {
    console.error(error instanceof Error ? error.stack : error);
    process.exitCode = 1;
});

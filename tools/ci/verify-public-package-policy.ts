import { promises as fs } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

type VendoredProtocolRuntimeEntryExport = {
    readonly exports: readonly string[];
    readonly source: string;
};

type PublicPackagePolicy = {
    readonly forbiddenRuntimeExports: readonly string[];
    readonly vendoredProtocolRuntimeEntryExports: readonly VendoredProtocolRuntimeEntryExport[];
    readonly vendoredProtocolRuntimeModules: readonly string[];
};

export const forbiddenRuntimeExports = [
    'bootstrap',
    'aggregateWitnessFromReceiverPlaintext',
    'createAggregateContributionFromBridgeProofRecord',
    'createAggregateReadyRecord',
    'createBallotProof',
    'createPendingBridgeProofRecordFromBridgeEvidence',
    'createPvssBallot',
    'createShamirPolynomial',
    'analyzeBgvCanonicalObject',
    'decodeBgvCanonicalObject',
    'decodeSparseTopKTarget',
    'decryptAggregateHistogram',
    'decryptAggregateScore',
    'decryptAggregateScoreBits',
    'decryptAggregateShare',
    'decryptComparisonInput',
    'decryptComparisonBit',
    'decryptEncryptedAggregate',
    'decryptExactSum',
    'decryptIntermediateWire',
    'decryptRank',
    'decryptReceiverPayload',
    'decryptTopKCiphertext',
    'decryptToFile',
    'decryptToString',
    'deriveAggregateContributionHash',
    'deriveAggregateReadyRecordHash',
    'deriveBallotPackageHash',
    'deriveBridgeProofProfileHash',
    'deriveBridgeProofRecordHash',
    'deriveBridgeProofStatementHash',
    'deriveBridgeProofTargetContractHash',
    'deriveCanonicalBallotSet',
    'deriveEncryptedAggregateReconstructionRoot',
    'derivePlaintextTopKOracle',
    'deriveReceiverShareVectors',
    'deriveTestAggregateShares',
    'deriveTestBallotPackage',
    'describeBgvOperationRegistry',
    'describeBgvRnsProfile',
    'dockerOracle',
    'encodeBgvBatchPlaintext',
    'exportAggregateOpening',
    'exportAggregateShare',
    'exportAggregateWitness',
    'exportBridgeWitness',
    'exportProofWitness',
    'exportSecretKey',
    'exportShare',
    'fieldModulus',
    'generateBgvBaseConversionFixture',
    'generateBgvCiphertextConventionFixture',
    'generateBgvPassiveSetupPackage',
    'generateAggregateBridgeEncryption',
    'getShare',
    'importSecretKey',
    'lattigoOracle',
    'oracleSerializer',
    'oracleVectorGenerator',
    'partialDecrypt',
    'partialDecryptWithoutTarget',
    'publishAggregateOpening',
    'rawBridgeWitness',
    'rawHEAdd',
    'rawHEMul',
    'rawHENoiseBudget',
    'rawHERelin',
    'rawHERotate',
    'rawNTT',
    'rawRNSLimbAccess',
    'setNoiseFloodSigma',
    'setSecretKey',
    'setSmudgingDistribution',
    'selectFirstValidAggregateContributions',
    'thresholdDecrypt',
    'verifyAggregateBridgeEncryption',
    'verifyAggregateContributionStructure',
    'verifyBallotPackageShell',
    'verifyBgvCiphertextObject',
    'verifyBgvLattigoOracle',
    'verifyBgvPlaintextObject',
    'verifyLattigoOracle',
    'verifyLocalReplayRecordShell',
    'verifyPvssBallotProof',
    'verifyTargetAcceptedRecordShell',
    'verifyTestAggregateShareOpening',
    'verifyTestShareCommitmentOpening',
    'verifyTopKDecryptionShareShell',
] as const;

export const vendoredProtocolRuntimeModules = [
    'board/hashes.ts',
    'board/index.ts',
    'board/shell-evidence.ts',
    'closing/index.ts',
    'common/verification-helpers.ts',
    'finality/hashes.ts',
    'finality/index.ts',
    'lifecycle/capabilities.ts',
    'lifecycle/labels.ts',
    'lifecycle/lifecycle.ts',
    'lifecycle/poll-spec.ts',
    'lifecycle/profiles.ts',
    'lifecycle/refusal.ts',
    'lifecycle/thresholds.ts',
    'ordering/index.ts',
    'recovery/index.ts',
    'roster/hashes.ts',
    'roster/inclusion.ts',
    'roster/index.ts',
    'roster/object-validation.ts',
    'roster/verification.ts',
] as const;

export const vendoredProtocolRuntimeEntryExports = [
    {
        source: 'board/index.js',
        exports: ['verifyBoardConsistency'],
    },
    {
        source: 'closing/index.js',
        exports: ['verifyCastReceiptShell', 'verifyCloseRecordShell'],
    },
    {
        source: 'finality/index.js',
        exports: ['verifyTargetFinality'],
    },
    {
        source: 'lifecycle/capabilities.js',
        exports: ['evaluateActionCapability'],
    },
    {
        source: 'lifecycle/labels.js',
        exports: ['deriveLifecycleLabels'],
    },
    {
        source: 'lifecycle/lifecycle.js',
        exports: ['isValidLifecycleTransition'],
    },
    {
        source: 'lifecycle/poll-spec.js',
        exports: ['derivePollSpecHash', 'validatePollSpec'],
    },
    {
        source: 'lifecycle/thresholds.js',
        exports: [
            'deriveFrozenRosterProfile',
            'deriveThresholdProfile',
            'deriveThresholdProfileHash',
        ],
    },
    {
        source: 'ordering/index.js',
        exports: ['deriveValidatedFirstValidOrder', 'verifyFirstValidPolicy'],
    },
    {
        source: 'recovery/index.js',
        exports: [
            'isActionCurrentForRecoveryEpoch',
            'verifyRecoveryEpochUpdate',
        ],
    },
    {
        source: 'roster/index.js',
        exports: [
            'verifyRosterExternalAcceptance',
            'verifyRosterManifestTranscript',
        ],
    },
] as const satisfies readonly VendoredProtocolRuntimeEntryExport[];

const publicPackagePolicy = {
    forbiddenRuntimeExports,
    vendoredProtocolRuntimeEntryExports,
    vendoredProtocolRuntimeModules,
} satisfies PublicPackagePolicy;

const repoRoot = fileURLToPath(new URL('../../', import.meta.url));
const sdkRuntimePath = path.resolve(
    repoRoot,
    'packages',
    'sdk',
    'dist',
    'index.js',
);
const protocolSourceDirectoryPath = path.resolve(
    repoRoot,
    'packages',
    'protocol',
    'src',
);

const sortedUnique = (values: readonly string[]): string[] =>
    [...new Set(values)].sort((left, right) => left.localeCompare(right));

const duplicates = (values: readonly string[]): string[] => {
    const seen = new Set<string>();
    const duplicateValues = new Set<string>();

    for (const value of values) {
        if (seen.has(value)) {
            duplicateValues.add(value);
        }
        seen.add(value);
    }

    return [...duplicateValues].sort((left, right) =>
        left.localeCompare(right),
    );
};

const protocolRuntimeSourcePathForEntrySource = (source: string): string =>
    source.replace(/\.js$/u, '.ts');

const isRelativeVendoredModulePath = (relativePath: string): boolean =>
    relativePath.endsWith('.ts') &&
    !relativePath.startsWith('/') &&
    !relativePath.startsWith('..') &&
    !path.isAbsolute(relativePath);

const validateUnique = (label: string, values: readonly string[]): string[] =>
    duplicates(values).map((value) => `${label} contains duplicate "${value}"`);

const validateVendoredProtocolRuntime = async (
    policy: PublicPackagePolicy,
    runtimeExports: ReadonlySet<string>,
): Promise<string[]> => {
    const failures: string[] = [];
    const vendoredModules = new Set(policy.vendoredProtocolRuntimeModules);

    failures.push(
        ...validateUnique(
            'vendoredProtocolRuntimeModules',
            policy.vendoredProtocolRuntimeModules,
        ),
        ...validateUnique(
            'vendoredProtocolRuntimeEntryExports sources',
            policy.vendoredProtocolRuntimeEntryExports.map(
                (entry) => entry.source,
            ),
        ),
    );

    for (const relativeSourcePath of policy.vendoredProtocolRuntimeModules) {
        if (!isRelativeVendoredModulePath(relativeSourcePath)) {
            failures.push(
                `vendoredProtocolRuntimeModules contains invalid path "${relativeSourcePath}"`,
            );
            continue;
        }

        try {
            await fs.access(
                path.resolve(protocolSourceDirectoryPath, relativeSourcePath),
            );
        } catch {
            failures.push(
                `vendoredProtocolRuntimeModules references missing source "${relativeSourcePath}"`,
            );
        }
    }

    for (const entry of policy.vendoredProtocolRuntimeEntryExports) {
        failures.push(
            ...validateUnique(
                `vendoredProtocolRuntimeEntryExports ${entry.source}`,
                entry.exports,
            ),
        );

        if (!entry.source.endsWith('.js')) {
            failures.push(
                `vendoredProtocolRuntimeEntryExports source "${entry.source}" must end with .js`,
            );
            continue;
        }

        const relativeSourcePath = protocolRuntimeSourcePathForEntrySource(
            entry.source,
        );
        if (!vendoredModules.has(relativeSourcePath)) {
            failures.push(
                `vendoredProtocolRuntimeEntryExports source "${entry.source}" is not listed in vendoredProtocolRuntimeModules`,
            );
        }

        for (const exportName of entry.exports) {
            if (!runtimeExports.has(exportName)) {
                failures.push(
                    `vendoredProtocolRuntimeEntryExports ${entry.source} exposes "${exportName}" outside the SDK runtime facade`,
                );
            }
        }
    }

    return failures.sort((left, right) => left.localeCompare(right));
};

export const validatePublicPackagePolicy = async (
    policy: PublicPackagePolicy,
    runtimeExports: readonly string[],
): Promise<string[]> => {
    const failures: string[] = [];
    const runtimeExportSet = new Set(runtimeExports);

    failures.push(
        ...validateUnique(
            'forbiddenRuntimeExports',
            policy.forbiddenRuntimeExports,
        ),
    );

    for (const exportName of policy.forbiddenRuntimeExports) {
        if (runtimeExportSet.has(exportName)) {
            failures.push(`Forbidden runtime export is public: ${exportName}`);
        }
    }

    failures.push(
        ...(await validateVendoredProtocolRuntime(policy, runtimeExportSet)),
    );

    return sortedUnique(failures);
};

const loadRuntimeExportNames = async (): Promise<string[]> => {
    const runtimeModule = (await import(
        pathToFileURL(sdkRuntimePath).href
    )) as Record<string, unknown>;

    return Object.keys(runtimeModule).sort((left, right) =>
        left.localeCompare(right),
    );
};

const main = async (): Promise<void> => {
    const failures = await validatePublicPackagePolicy(
        publicPackagePolicy,
        await loadRuntimeExportNames(),
    );

    if (failures.length > 0) {
        throw new Error(failures.join('\n'));
    }

    console.log('Public package policy verification passed.');
};

const scriptEntryPoint = process.argv[1];
const isMainModule =
    scriptEntryPoint !== undefined &&
    import.meta.url === pathToFileURL(scriptEntryPoint).href;

if (isMainModule) {
    void main();
}

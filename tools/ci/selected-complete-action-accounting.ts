import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';

import { foundationProfile } from '#packages/types/src/foundation-contract.js';
import type { DesktopBrowserCommonProofMeasurement } from '#packages/protocol/tests/support/desktop-browser-common-proof-measurement';
import { validateDesktopBrowserCommonProofMeasurement } from '#packages/protocol/tests/support/desktop-browser-common-proof-measurement-worker-protocol';
import type { DesktopBrowserEvaluatorReplayMeasurement } from '#packages/protocol/tests/support/desktop-browser-evaluator-replay-measurement';
import { validateDesktopBrowserEvaluatorReplayMeasurement } from '#packages/protocol/tests/support/desktop-browser-evaluator-replay-measurement-worker-protocol';
import { productionDesktopBrowserEvaluatorReplayMeasurementCaseIdentifier } from '#packages/protocol/tests/support/desktop-browser-evaluator-replay-measurement-case-identifier';
import {
    orderedProductionCommonProofMeasurementCases,
} from '#packages/protocol/tests/support/production-common-proof-measurement-case-registry';

import { wasmStackByteLength } from './build-wasm-kernel.js';

const generatedAccountingFileName =
    'selected-complete-action-generated-byte-accounting.json';
const combinedAccountingFileName = 'selected-complete-action-accounting.json';
const lowercaseHash512Pattern = /^[a-f0-9]{128}$/u;
const decimalIntegerPattern = /^(?:0|[1-9][0-9]*)$/u;

const orderedCorpusOwnerNames = Object.freeze([
    'setup-public-corpus',
    'setup-private-mailbox-corpus',
    'ballot-public-corpus',
    'evaluator-public-corpus',
    'finality-public-corpus',
    'target-release-public-corpus',
] as const);

type CorpusOwnerName = (typeof orderedCorpusOwnerNames)[number];

type CompleteActionIdentity = Readonly<{
    actionContextHash: string;
    aggregateSourceObjectHash: string;
    ceremonyContextHash: string;
    evaluatorReplayObjectHash: string;
    finalityHash: string;
    rosterHash: string;
    setupPackageHash: string;
    suiteIdentifier: string;
    topCount: number;
}>;

type CorpusOwnerRow = Readonly<{
    canonicalWireByteLength: number;
    codecAndProofCeilingWireByteLength: number;
    completeVerifierDownloadByteLength: number;
    owner: CorpusOwnerName;
    privateMailboxStorageByteLength: number;
    producerUploadByteLength: number;
    publicStorageByteLength: number;
}>;

type KmacInputClassAccounting = Readonly<{
    actionKeyHierarchyDerivationCount: number;
    attemptIdentifierDerivationCount: number;
    committedMaterialInnerDerivationCount: number;
    privateStreamBlockCount: number;
    totalCount: number;
}>;

type SourceModeledResources = Readonly<{
    evaluatorSourceResidentByteLengthPerParticipant: number;
    finalEvaluatorKeyStoreResidentByteLength: number;
    maximumBoundaryCopiedBufferByteLength: number;
    proofGenerationExternalScratchPeakByteLength: number;
    proofGenerationResidentPeakByteLengthExcludingWasmStack: number;
}>;

type CompleteActionTotals = Readonly<{
    canonicalWireByteLength: number;
    codecAndProofCeilingWireByteLength: number;
    completeVerifierDownloadByteLength: number;
    generatedProofWireByteLength: number;
    maximumPrivateMailboxRecipientDownloadByteLength: number;
    privateMailboxStorageByteLength: number;
    producerUploadByteLength: number;
    proofCeilingWireByteLength: number;
    publicStorageByteLength: number;
}>;

export type SelectedCompleteActionGeneratedByteAccounting = Readonly<{
    applicationSoundnessAccounting: Readonly<Record<string, unknown>>;
    identity: CompleteActionIdentity;
    ownerRows: readonly CorpusOwnerRow[];
    privateRandomnessKmacInputAccounting: Readonly<{
        ceremony: KmacInputClassAccounting;
        completeAction: KmacInputClassAccounting;
        proofPrivacy: KmacInputClassAccounting;
    }>;
    recordKind: 'selected-complete-action-generated-byte-accounting';
    recordVersion: 2;
    samplerAvailabilityAccounting: Readonly<Record<string, unknown>>;
    sourceModeledResources: SourceModeledResources;
    totals: CompleteActionTotals;
}>;

export type DesktopBrowserProcessMemoryMeasurement = Readonly<{
    baselineProcessTreeResidentMemoryBytes: number;
    caseIdentifier: string;
    measurementScope: 'isolated-desktop-chromium-process-tree';
    observedPeakProcessTreeResidentMemoryBytes: number;
    processTreeResidentMemoryIncreaseBytes: number;
}>;

export type CommonProofAccountingEvidenceRow = Readonly<{
    measurement: DesktopBrowserCommonProofMeasurement;
    processMemory: DesktopBrowserProcessMemoryMeasurement;
}>;

export type EvaluatorReplayAccountingEvidenceRow = Readonly<{
    measurement: DesktopBrowserEvaluatorReplayMeasurement;
    processMemory: DesktopBrowserProcessMemoryMeasurement;
}>;

const requirePlainRecord = (
    value: unknown,
    fieldName: string,
): Record<string, unknown> => {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        throw new Error(`${fieldName} must be an object.`);
    }
    return value as Record<string, unknown>;
};

const requireExactKeys = (
    record: Readonly<Record<string, unknown>>,
    requiredKeys: readonly string[],
    fieldName: string,
): void => {
    const actualKeys = Object.keys(record).sort();
    const expectedKeys = [...requiredKeys].sort();
    if (
        actualKeys.length !== expectedKeys.length ||
        actualKeys.some((key, keyIndex) => key !== expectedKeys[keyIndex])
    ) {
        throw new Error(`${fieldName} does not have the exact source-owned fields.`);
    }
};

const requireExactNonnegativeInteger = (
    value: unknown,
    fieldName: string,
): number => {
    if (!Number.isSafeInteger(value) || Number(value) < 0) {
        throw new Error(`${fieldName} must be an exact nonnegative integer.`);
    }
    return Number(value);
};

const requireExactPositiveInteger = (
    value: unknown,
    fieldName: string,
): number => {
    const integer = requireExactNonnegativeInteger(value, fieldName);
    if (integer === 0) {
        throw new Error(`${fieldName} must be positive.`);
    }
    return integer;
};

const checkedAdd = (
    left: number,
    right: number,
    fieldName: string,
): number => {
    const sum = left + right;
    if (!Number.isSafeInteger(sum)) {
        throw new Error(`${fieldName} exceeds the exact integer range.`);
    }
    return sum;
};

const requireHash512 = (value: unknown, fieldName: string): string => {
    if (typeof value !== 'string' || !lowercaseHash512Pattern.test(value)) {
        throw new Error(`${fieldName} must be one lowercase Hash512 digest.`);
    }
    return value;
};

const requireDecimalInteger = (value: unknown, fieldName: string): string => {
    if (typeof value !== 'string' || !decimalIntegerPattern.test(value)) {
        throw new Error(`${fieldName} must be a canonical decimal integer string.`);
    }
    return value;
};

const requireOptionalSelector = (
    value: unknown,
    fieldName: string,
): number | null =>
    value === null
        ? null
        : requireExactNonnegativeInteger(value, fieldName);

const requireDyadicProbability = (value: unknown, fieldName: string): void => {
    const record = requirePlainRecord(value, fieldName);
    requireExactKeys(
        record,
        ['denominatorPowerOfTwoExponent', 'numerator'],
        fieldName,
    );
    requireExactNonnegativeInteger(
        record.denominatorPowerOfTwoExponent,
        `${fieldName}.denominatorPowerOfTwoExponent`,
    );
    requireDecimalInteger(record.numerator, `${fieldName}.numerator`);
};

const requireExactProbability = (value: unknown, fieldName: string): void => {
    const record = requirePlainRecord(value, fieldName);
    requireExactKeys(record, ['denominator', 'numerator'], fieldName);
    const denominator = requireDecimalInteger(
        record.denominator,
        `${fieldName}.denominator`,
    );
    if (denominator === '0') {
        throw new Error(`${fieldName}.denominator must be positive.`);
    }
    requireDecimalInteger(record.numerator, `${fieldName}.numerator`);
};

const requireCompleteActionIdentity = (
    value: unknown,
): CompleteActionIdentity => {
    const record = requirePlainRecord(value, 'Generated accounting identity');
    requireExactKeys(
        record,
        [
            'actionContextHash',
            'aggregateSourceObjectHash',
            'ceremonyContextHash',
            'evaluatorReplayObjectHash',
            'finalityHash',
            'rosterHash',
            'setupPackageHash',
            'suiteIdentifier',
            'topCount',
        ],
        'Generated accounting identity',
    );
    return Object.freeze({
        actionContextHash: requireHash512(
            record.actionContextHash,
            'Generated accounting identity.actionContextHash',
        ),
        aggregateSourceObjectHash: requireHash512(
            record.aggregateSourceObjectHash,
            'Generated accounting identity.aggregateSourceObjectHash',
        ),
        ceremonyContextHash: requireHash512(
            record.ceremonyContextHash,
            'Generated accounting identity.ceremonyContextHash',
        ),
        evaluatorReplayObjectHash: requireHash512(
            record.evaluatorReplayObjectHash,
            'Generated accounting identity.evaluatorReplayObjectHash',
        ),
        finalityHash: requireHash512(
            record.finalityHash,
            'Generated accounting identity.finalityHash',
        ),
        rosterHash: requireHash512(
            record.rosterHash,
            'Generated accounting identity.rosterHash',
        ),
        setupPackageHash: requireHash512(
            record.setupPackageHash,
            'Generated accounting identity.setupPackageHash',
        ),
        suiteIdentifier: requireHash512(
            record.suiteIdentifier,
            'Generated accounting identity.suiteIdentifier',
        ),
        topCount: requireExactPositiveInteger(
            record.topCount,
            'Generated accounting identity.topCount',
        ),
    });
};

const requireCorpusOwnerName = (value: unknown): CorpusOwnerName => {
    if (
        typeof value !== 'string' ||
        !orderedCorpusOwnerNames.some((owner) => owner === value)
    ) {
        throw new Error('Generated accounting contains an unknown corpus owner.');
    }
    return value as CorpusOwnerName;
};

const requireCorpusOwnerRows = (value: unknown): readonly CorpusOwnerRow[] => {
    if (!Array.isArray(value)) {
        throw new Error('Generated accounting ownerRows must be an array.');
    }
    const observedOwners = new Set<CorpusOwnerName>();
    const rows = value.map((rowValue, rowIndex) => {
        const fieldName = `Generated accounting ownerRows[${rowIndex}]`;
        const record = requirePlainRecord(rowValue, fieldName);
        requireExactKeys(
            record,
            [
                'canonicalWireByteLength',
                'codecAndProofCeilingWireByteLength',
                'completeVerifierDownloadByteLength',
                'owner',
                'privateMailboxStorageByteLength',
                'producerUploadByteLength',
                'publicStorageByteLength',
            ],
            fieldName,
        );
        const owner = requireCorpusOwnerName(record.owner);
        if (observedOwners.has(owner)) {
            throw new Error(`Generated accounting duplicates corpus owner ${owner}.`);
        }
        observedOwners.add(owner);
        const canonicalWireByteLength = requireExactPositiveInteger(
            record.canonicalWireByteLength,
            `${fieldName}.canonicalWireByteLength`,
        );
        const codecAndProofCeilingWireByteLength =
            requireExactPositiveInteger(
                record.codecAndProofCeilingWireByteLength,
                `${fieldName}.codecAndProofCeilingWireByteLength`,
            );
        const completeVerifierDownloadByteLength =
            requireExactNonnegativeInteger(
                record.completeVerifierDownloadByteLength,
                `${fieldName}.completeVerifierDownloadByteLength`,
            );
        const privateMailboxStorageByteLength =
            requireExactNonnegativeInteger(
                record.privateMailboxStorageByteLength,
                `${fieldName}.privateMailboxStorageByteLength`,
            );
        const producerUploadByteLength = requireExactPositiveInteger(
            record.producerUploadByteLength,
            `${fieldName}.producerUploadByteLength`,
        );
        const publicStorageByteLength = requireExactNonnegativeInteger(
            record.publicStorageByteLength,
            `${fieldName}.publicStorageByteLength`,
        );
        if (
            codecAndProofCeilingWireByteLength < canonicalWireByteLength ||
            producerUploadByteLength !== canonicalWireByteLength ||
            publicStorageByteLength + privateMailboxStorageByteLength !==
                canonicalWireByteLength ||
            completeVerifierDownloadByteLength !== publicStorageByteLength
        ) {
            throw new Error(`${fieldName} does not partition its exact bytes.`);
        }
        if (
            (owner === 'setup-private-mailbox-corpus') !==
            (privateMailboxStorageByteLength > 0)
        ) {
            throw new Error(`${fieldName} assigns bytes to the wrong storage owner.`);
        }
        return Object.freeze({
            canonicalWireByteLength,
            codecAndProofCeilingWireByteLength,
            completeVerifierDownloadByteLength,
            owner,
            privateMailboxStorageByteLength,
            producerUploadByteLength,
            publicStorageByteLength,
        });
    });
    if (
        rows.length !== orderedCorpusOwnerNames.length ||
        orderedCorpusOwnerNames.some((owner) => !observedOwners.has(owner))
    ) {
        throw new Error('Generated accounting omits one or more corpus owners.');
    }
    rows.sort(
        (left, right) =>
            orderedCorpusOwnerNames.indexOf(left.owner) -
            orderedCorpusOwnerNames.indexOf(right.owner),
    );
    return Object.freeze(rows);
};

const requireKmacInputClassAccounting = (
    value: unknown,
    fieldName: string,
): KmacInputClassAccounting => {
    const record = requirePlainRecord(value, fieldName);
    const classNames = [
        'actionKeyHierarchyDerivationCount',
        'attemptIdentifierDerivationCount',
        'committedMaterialInnerDerivationCount',
        'privateStreamBlockCount',
    ] as const;
    requireExactKeys(record, [...classNames, 'totalCount'], fieldName);
    const accounting = Object.fromEntries(
        classNames.map((className) => [
            className,
            requireExactNonnegativeInteger(
                record[className],
                `${fieldName}.${className}`,
            ),
        ]),
    ) as unknown as Omit<KmacInputClassAccounting, 'totalCount'>;
    const totalCount = classNames.reduce(
        (total, className) =>
            checkedAdd(total, accounting[className], `${fieldName}.totalCount`),
        0,
    );
    if (
        requireExactNonnegativeInteger(
            record.totalCount,
            `${fieldName}.totalCount`,
        ) !== totalCount
    ) {
        throw new Error(`${fieldName}.totalCount does not equal its four classes.`);
    }
    return Object.freeze({ ...accounting, totalCount });
};

const requireSourceModeledResources = (
    value: unknown,
): SourceModeledResources => {
    const record = requirePlainRecord(value, 'Generated accounting resources');
    const fields = [
        'evaluatorSourceResidentByteLengthPerParticipant',
        'finalEvaluatorKeyStoreResidentByteLength',
        'maximumBoundaryCopiedBufferByteLength',
        'proofGenerationExternalScratchPeakByteLength',
        'proofGenerationResidentPeakByteLengthExcludingWasmStack',
    ] as const;
    requireExactKeys(record, fields, 'Generated accounting resources');
    return Object.freeze(
        Object.fromEntries(
            fields.map((fieldName) => [
                fieldName,
                requireExactPositiveInteger(
                    record[fieldName],
                    `Generated accounting resources.${fieldName}`,
                ),
            ]),
        ) as unknown as SourceModeledResources,
    );
};

const requireCompleteActionTotals = (value: unknown): CompleteActionTotals => {
    const record = requirePlainRecord(value, 'Generated accounting totals');
    const fields = [
        'canonicalWireByteLength',
        'codecAndProofCeilingWireByteLength',
        'completeVerifierDownloadByteLength',
        'generatedProofWireByteLength',
        'maximumPrivateMailboxRecipientDownloadByteLength',
        'privateMailboxStorageByteLength',
        'producerUploadByteLength',
        'proofCeilingWireByteLength',
        'publicStorageByteLength',
    ] as const;
    requireExactKeys(record, fields, 'Generated accounting totals');
    return Object.freeze(
        Object.fromEntries(
            fields.map((fieldName) => [
                fieldName,
                requireExactPositiveInteger(
                    record[fieldName],
                    `Generated accounting totals.${fieldName}`,
                ),
            ]),
        ) as unknown as CompleteActionTotals,
    );
};

const requireSamplerAvailabilityAccounting = (
    value: unknown,
): Readonly<Record<string, unknown>> => {
    const record = requirePlainRecord(value, 'Sampler availability accounting');
    requireExactKeys(
        record,
        [
            'completeActionExhaustionProbabilityUpperBound',
            'physicalProofObjectCount',
            'variantRows',
        ],
        'Sampler availability accounting',
    );
    requireDyadicProbability(
        record.completeActionExhaustionProbabilityUpperBound,
        'Sampler availability accounting.completeActionExhaustionProbabilityUpperBound',
    );
    const physicalProofObjectCount = requireExactPositiveInteger(
        record.physicalProofObjectCount,
        'Sampler availability accounting.physicalProofObjectCount',
    );
    if (!Array.isArray(record.variantRows) || record.variantRows.length === 0) {
        throw new Error('Sampler availability accounting variantRows must be nonempty.');
    }
    const observedSelectors = new Set<string>();
    let accountedProofObjectCount = 0;
    for (const [rowIndex, rowValue] of record.variantRows.entries()) {
        const row = requirePlainRecord(
            rowValue,
            `Sampler availability accounting.variantRows[${rowIndex}]`,
        );
        const schemaIdentifier = requireExactPositiveInteger(
            row.applicationStatementSchemaIdentifier,
            `Sampler availability accounting.variantRows[${rowIndex}].applicationStatementSchemaIdentifier`,
        );
        const schedulePosition = requireOptionalSelector(
            row.schedulePosition,
            `Sampler availability accounting.variantRows[${rowIndex}].schedulePosition`,
        );
        const topCount = requireOptionalSelector(
            row.topCount,
            `Sampler availability accounting.variantRows[${rowIndex}].topCount`,
        );
        const selectorKey = `${schemaIdentifier}:${schedulePosition ?? '-'}:${topCount ?? '-'}`;
        if (observedSelectors.has(selectorKey)) {
            throw new Error(`Sampler availability accounting duplicates selector ${selectorKey}.`);
        }
        observedSelectors.add(selectorKey);
        accountedProofObjectCount = checkedAdd(
            accountedProofObjectCount,
            requireExactPositiveInteger(
                row.applicationMultiplicity,
                `Sampler availability accounting.variantRows[${rowIndex}].applicationMultiplicity`,
            ),
            'Sampler availability accounting physical proof count',
        );
        requireDyadicProbability(
            row.combinedExhaustionProbabilityUpperBound,
            `Sampler availability accounting.variantRows[${rowIndex}].combinedExhaustionProbabilityUpperBound`,
        );
    }
    if (accountedProofObjectCount !== physicalProofObjectCount) {
        throw new Error('Sampler availability accounting omits physical proof objects.');
    }
    return Object.freeze(record);
};

const requireApplicationSoundnessAccounting = (
    value: unknown,
    expectedVariantCount: number,
): Readonly<Record<string, unknown>> => {
    const record = requirePlainRecord(value, 'Application soundness accounting');
    requireExactKeys(
        record,
        [
            'ordinaryInvalidAcceptanceBound',
            'quantumRandomOracleInvalidAcceptanceBound',
            'roundByRoundCompilerInputBound',
            'variantRows',
        ],
        'Application soundness accounting',
    );
    requireExactProbability(
        record.ordinaryInvalidAcceptanceBound,
        'Application soundness accounting.ordinaryInvalidAcceptanceBound',
    );
    requireExactProbability(
        record.quantumRandomOracleInvalidAcceptanceBound,
        'Application soundness accounting.quantumRandomOracleInvalidAcceptanceBound',
    );
    requireExactProbability(
        record.roundByRoundCompilerInputBound,
        'Application soundness accounting.roundByRoundCompilerInputBound',
    );
    if (
        !Array.isArray(record.variantRows) ||
        record.variantRows.length !== expectedVariantCount
    ) {
        throw new Error('Application soundness accounting has an incomplete variant inventory.');
    }
    const observedCatalogIndexes = new Set<number>();
    for (const [rowIndex, rowValue] of record.variantRows.entries()) {
        const row = requirePlainRecord(
            rowValue,
            `Application soundness accounting.variantRows[${rowIndex}]`,
        );
        const catalogIndex = requireExactNonnegativeInteger(
            row.variantCatalogIndex,
            `Application soundness accounting.variantRows[${rowIndex}].variantCatalogIndex`,
        );
        if (observedCatalogIndexes.has(catalogIndex)) {
            throw new Error(`Application soundness accounting duplicates catalog index ${catalogIndex}.`);
        }
        observedCatalogIndexes.add(catalogIndex);
        requireExactProbability(
            row.quantumRandomOracleSingleEventBound,
            `Application soundness accounting.variantRows[${rowIndex}].quantumRandomOracleSingleEventBound`,
        );
        requireExactProbability(
            row.roundByRoundErrorBound,
            `Application soundness accounting.variantRows[${rowIndex}].roundByRoundErrorBound`,
        );
        const transitions = requirePlainRecord(
            row.theoremTransitionCounts,
            `Application soundness accounting.variantRows[${rowIndex}].theoremTransitionCounts`,
        );
        const transitionFields = [
            'compositionBatchingTransitionCount',
            'compositionCoefficientCount',
            'deepPointTransitionCount',
            'friFoldTransitionCount',
            'maximumCandidateDrawsPerOutput',
            'openingBatchMcaTransitionCount',
            'orderedNonNativeChallengeGroupCount',
            'queryVectorPositionCount',
            'queryVectorTransitionCount',
        ] as const;
        requireExactKeys(
            transitions,
            transitionFields,
            `Application soundness accounting.variantRows[${rowIndex}].theoremTransitionCounts`,
        );
        for (const fieldName of transitionFields) {
            requireExactNonnegativeInteger(
                transitions[fieldName],
                `Application soundness accounting.variantRows[${rowIndex}].theoremTransitionCounts.${fieldName}`,
            );
        }
        if (
            transitions.compositionBatchingTransitionCount !== 1 ||
            transitions.deepPointTransitionCount !== 1 ||
            transitions.queryVectorTransitionCount !== 1 ||
            Number(transitions.friFoldTransitionCount) === 0 ||
            Number(transitions.queryVectorPositionCount) === 0
        ) {
            throw new Error('Application soundness accounting contains an invalid theorem transition row.');
        }
    }
    return Object.freeze(record);
};

export const validateSelectedCompleteActionGeneratedByteAccounting = (
    value: unknown,
): SelectedCompleteActionGeneratedByteAccounting => {
    const record = requirePlainRecord(value, 'Generated complete-action accounting');
    requireExactKeys(
        record,
        [
            'applicationSoundnessAccounting',
            'identity',
            'ownerRows',
            'privateRandomnessKmacInputAccounting',
            'recordKind',
            'recordVersion',
            'samplerAvailabilityAccounting',
            'sourceModeledResources',
            'totals',
        ],
        'Generated complete-action accounting',
    );
    if (
        record.recordKind !==
            'selected-complete-action-generated-byte-accounting' ||
        record.recordVersion !== 2
    ) {
        throw new Error('Generated complete-action accounting has an unsupported schema.');
    }
    const identity = requireCompleteActionIdentity(record.identity);
    if (identity.topCount !== foundationProfile.optionCount) {
        throw new Error('Generated complete-action accounting does not use the selected action.');
    }
    const ownerRows = requireCorpusOwnerRows(record.ownerRows);
    const totals = requireCompleteActionTotals(record.totals);
    const summedTotals = ownerRows.reduce(
        (current, row) => ({
            canonicalWireByteLength: checkedAdd(
                current.canonicalWireByteLength,
                row.canonicalWireByteLength,
                'Generated canonical corpus total',
            ),
            codecAndProofCeilingWireByteLength: checkedAdd(
                current.codecAndProofCeilingWireByteLength,
                row.codecAndProofCeilingWireByteLength,
                'Generated codec-and-proof corpus total',
            ),
            completeVerifierDownloadByteLength: checkedAdd(
                current.completeVerifierDownloadByteLength,
                row.completeVerifierDownloadByteLength,
                'Generated verifier download total',
            ),
            privateMailboxStorageByteLength: checkedAdd(
                current.privateMailboxStorageByteLength,
                row.privateMailboxStorageByteLength,
                'Generated private mailbox storage total',
            ),
            producerUploadByteLength: checkedAdd(
                current.producerUploadByteLength,
                row.producerUploadByteLength,
                'Generated producer upload total',
            ),
            publicStorageByteLength: checkedAdd(
                current.publicStorageByteLength,
                row.publicStorageByteLength,
                'Generated public storage total',
            ),
        }),
        {
            canonicalWireByteLength: 0,
            codecAndProofCeilingWireByteLength: 0,
            completeVerifierDownloadByteLength: 0,
            privateMailboxStorageByteLength: 0,
            producerUploadByteLength: 0,
            publicStorageByteLength: 0,
        },
    );
    for (const fieldName of Object.keys(summedTotals) as Array<
        keyof typeof summedTotals
    >) {
        if (summedTotals[fieldName] !== totals[fieldName]) {
            throw new Error(`Generated accounting total ${fieldName} does not match its owners.`);
        }
    }
    if (
        totals.generatedProofWireByteLength > totals.proofCeilingWireByteLength ||
        totals.publicStorageByteLength >
            foundationProfile.maximumCanonicalStreamByteLength ||
        totals.completeVerifierDownloadByteLength >
            foundationProfile.maximumCanonicalStreamByteLength ||
        totals.maximumPrivateMailboxRecipientDownloadByteLength >
            foundationProfile.maximumCanonicalStreamByteLength
    ) {
        throw new Error('Generated accounting exceeds an absolute stream or proof bound.');
    }
    const sourceModeledResources = requireSourceModeledResources(
        record.sourceModeledResources,
    );
    if (
        sourceModeledResources.maximumBoundaryCopiedBufferByteLength >
        foundationProfile.maximumCopiedBufferByteLength
    ) {
        throw new Error('Generated accounting exceeds the absolute copied-buffer bound.');
    }
    const modeledResidentByteLengthIncludingWasmStack = checkedAdd(
        sourceModeledResources.proofGenerationResidentPeakByteLengthExcludingWasmStack,
        wasmStackByteLength,
        'Modeled resident memory including the WASM stack',
    );
    if (
        modeledResidentByteLengthIncludingWasmStack >
        foundationProfile.maximumWasmMemoryByteLength
    ) {
        throw new Error('Generated accounting exceeds the absolute WASM-memory bound.');
    }
    const privateRandomnessRecord = requirePlainRecord(
        record.privateRandomnessKmacInputAccounting,
        'Private-randomness KMAC accounting',
    );
    requireExactKeys(
        privateRandomnessRecord,
        ['ceremony', 'completeAction', 'proofPrivacy'],
        'Private-randomness KMAC accounting',
    );
    const ceremony = requireKmacInputClassAccounting(
        privateRandomnessRecord.ceremony,
        'Private-randomness KMAC accounting.ceremony',
    );
    const proofPrivacy = requireKmacInputClassAccounting(
        privateRandomnessRecord.proofPrivacy,
        'Private-randomness KMAC accounting.proofPrivacy',
    );
    const completeAction = requireKmacInputClassAccounting(
        privateRandomnessRecord.completeAction,
        'Private-randomness KMAC accounting.completeAction',
    );
    for (const className of [
        'actionKeyHierarchyDerivationCount',
        'attemptIdentifierDerivationCount',
        'committedMaterialInnerDerivationCount',
        'privateStreamBlockCount',
        'totalCount',
    ] as const) {
        if (
            completeAction[className] !==
            checkedAdd(
                ceremony[className],
                proofPrivacy[className],
                `Private-randomness KMAC accounting.completeAction.${className}`,
            )
        ) {
            throw new Error(`Private-randomness KMAC class ${className} is not additive.`);
        }
    }
    const samplerAvailabilityAccounting =
        requireSamplerAvailabilityAccounting(
            record.samplerAvailabilityAccounting,
        );
    const samplerVariantRows = samplerAvailabilityAccounting.variantRows;
    if (!Array.isArray(samplerVariantRows)) {
        throw new Error('Sampler availability accounting variantRows must be an array.');
    }
    const applicationSoundnessAccounting =
        requireApplicationSoundnessAccounting(
            record.applicationSoundnessAccounting,
            samplerVariantRows.length,
        );
    return Object.freeze({
        applicationSoundnessAccounting,
        identity,
        ownerRows,
        privateRandomnessKmacInputAccounting: Object.freeze({
            ceremony,
            completeAction,
            proofPrivacy,
        }),
        recordKind: 'selected-complete-action-generated-byte-accounting',
        recordVersion: 2,
        samplerAvailabilityAccounting,
        sourceModeledResources,
        totals,
    });
};

export const validateDesktopBrowserProcessMemoryMeasurement = (
    value: unknown,
    caseIdentifier: string,
): DesktopBrowserProcessMemoryMeasurement => {
    const record = requirePlainRecord(value, `Process-memory measurement ${caseIdentifier}`);
    requireExactKeys(
        record,
        [
            'baselineProcessTreeResidentMemoryBytes',
            'caseIdentifier',
            'measurementScope',
            'observedPeakProcessTreeResidentMemoryBytes',
            'processTreeResidentMemoryIncreaseBytes',
        ],
        `Process-memory measurement ${caseIdentifier}`,
    );
    if (
        record.caseIdentifier !== caseIdentifier ||
        record.measurementScope !== 'isolated-desktop-chromium-process-tree'
    ) {
        throw new Error(`Process-memory measurement ${caseIdentifier} has a mismatched owner.`);
    }
    const baselineProcessTreeResidentMemoryBytes = requireExactNonnegativeInteger(
        record.baselineProcessTreeResidentMemoryBytes,
        `Process-memory measurement ${caseIdentifier}.baselineProcessTreeResidentMemoryBytes`,
    );
    const observedPeakProcessTreeResidentMemoryBytes =
        requireExactNonnegativeInteger(
            record.observedPeakProcessTreeResidentMemoryBytes,
            `Process-memory measurement ${caseIdentifier}.observedPeakProcessTreeResidentMemoryBytes`,
        );
    const processTreeResidentMemoryIncreaseBytes =
        requireExactNonnegativeInteger(
            record.processTreeResidentMemoryIncreaseBytes,
            `Process-memory measurement ${caseIdentifier}.processTreeResidentMemoryIncreaseBytes`,
        );
    if (
        observedPeakProcessTreeResidentMemoryBytes -
            baselineProcessTreeResidentMemoryBytes !==
        processTreeResidentMemoryIncreaseBytes
    ) {
        throw new Error(`Process-memory measurement ${caseIdentifier} is not internally exact.`);
    }
    return Object.freeze({
        baselineProcessTreeResidentMemoryBytes,
        caseIdentifier,
        measurementScope: 'isolated-desktop-chromium-process-tree',
        observedPeakProcessTreeResidentMemoryBytes,
        processTreeResidentMemoryIncreaseBytes,
    });
};

const commonIdentityFields = [
    'actionContextHash',
    'manifestHash',
    'packagedWasmSha256',
    'runtimeBuildManifestHash',
    'suiteIdentifier',
] as const;

const requireMatchingGlobalMeasurementIdentity = (
    reference: DesktopBrowserCommonProofMeasurement['measurementIdentity'],
    candidate: DesktopBrowserCommonProofMeasurement['measurementIdentity'],
    caseIdentifier: string,
): void => {
    for (const fieldName of commonIdentityFields) {
        if (candidate[fieldName] !== reference[fieldName]) {
            throw new Error(`Desktop-browser measurement ${caseIdentifier} has a mismatched ${fieldName}.`);
        }
    }
};

const commonProofFamilyName = (caseIdentifier: string): string =>
    caseIdentifier.replace(/-(?:fresh|resumed)$/u, '');

export const assembleSelectedCompleteActionAccounting = (input: Readonly<{
    commonProofEvidenceRows: readonly CommonProofAccountingEvidenceRow[];
    evaluatorReplayEvidenceRow: EvaluatorReplayAccountingEvidenceRow;
    generatedAccounting: SelectedCompleteActionGeneratedByteAccounting;
}>): Readonly<Record<string, unknown>> => {
    const commonRowsByIdentifier = new Map<string, CommonProofAccountingEvidenceRow>();
    for (const row of input.commonProofEvidenceRows) {
        const caseIdentifier = row.measurement.caseIdentifier;
        if (commonRowsByIdentifier.has(caseIdentifier)) {
            throw new Error(`Desktop-browser accounting duplicates empirical owner ${caseIdentifier}.`);
        }
        if (row.processMemory.caseIdentifier !== caseIdentifier) {
            throw new Error(`Desktop-browser accounting joins mismatched operation and process owners for ${caseIdentifier}.`);
        }
        commonRowsByIdentifier.set(caseIdentifier, row);
    }
    const orderedCommonRows = orderedProductionCommonProofMeasurementCases.map(
        (requiredCase) => {
            const row = commonRowsByIdentifier.get(requiredCase.caseIdentifier);
            if (row === undefined) {
                throw new Error(`Desktop-browser accounting omits empirical owner ${requiredCase.caseIdentifier}.`);
            }
            if (row.measurement.executionKind !== requiredCase.executionKind) {
                throw new Error(`Desktop-browser accounting has the wrong execution kind for ${requiredCase.caseIdentifier}.`);
            }
            return row;
        },
    );
    if (commonRowsByIdentifier.size !== orderedCommonRows.length) {
        throw new Error('Desktop-browser accounting contains an unexpected empirical owner.');
    }
    const evaluatorReplayMeasurement = input.evaluatorReplayEvidenceRow.measurement;
    const evaluatorReplayProcessMemory = input.evaluatorReplayEvidenceRow.processMemory;
    if (
        evaluatorReplayMeasurement.caseIdentifier !==
            productionDesktopBrowserEvaluatorReplayMeasurementCaseIdentifier ||
        evaluatorReplayProcessMemory.caseIdentifier !==
            productionDesktopBrowserEvaluatorReplayMeasurementCaseIdentifier
    ) {
        throw new Error('Desktop-browser accounting omits the selected evaluator-replay owner.');
    }
    const referenceIdentity = orderedCommonRows[0]?.measurement.measurementIdentity;
    if (referenceIdentity === undefined) {
        throw new Error('Desktop-browser accounting has no common-proof identity.');
    }
    for (const row of orderedCommonRows) {
        requireMatchingGlobalMeasurementIdentity(
            referenceIdentity,
            row.measurement.measurementIdentity,
            row.measurement.caseIdentifier,
        );
    }
    requireMatchingGlobalMeasurementIdentity(
        referenceIdentity,
        evaluatorReplayMeasurement.measurementIdentity,
        evaluatorReplayMeasurement.caseIdentifier,
    );
    if (
        referenceIdentity.suiteIdentifier !==
            input.generatedAccounting.identity.suiteIdentifier ||
        referenceIdentity.actionContextHash !==
            input.generatedAccounting.identity.actionContextHash
    ) {
        throw new Error('Generated objects and desktop-browser evidence have mismatched action identity.');
    }
    const pairedRows = new Map<string, CommonProofAccountingEvidenceRow[]>();
    for (const row of orderedCommonRows) {
        const familyName = commonProofFamilyName(row.measurement.caseIdentifier);
        const rows = pairedRows.get(familyName) ?? [];
        rows.push(row);
        pairedRows.set(familyName, rows);
    }
    for (const [familyName, rows] of pairedRows) {
        const fresh = rows.find((row) => row.measurement.executionKind === 'fresh');
        const resumed = rows.find((row) => row.measurement.executionKind === 'resumed');
        if (rows.length !== 2 || fresh === undefined || resumed === undefined) {
            throw new Error(`Desktop-browser accounting has an incomplete ${familyName} fresh/resumed pair.`);
        }
        if (
            JSON.stringify(fresh.measurement.measurementIdentity) !==
                JSON.stringify(resumed.measurement.measurementIdentity) ||
            fresh.measurement.publicOutputHashes.canonicalProofStreamSha512 !==
                resumed.measurement.publicOutputHashes.canonicalProofStreamSha512 ||
            fresh.measurement.canonicalOutputTraffic.committedByteLength !==
                resumed.measurement.canonicalOutputTraffic.committedByteLength
        ) {
            throw new Error(`Desktop-browser accounting ${familyName} fresh/resumed outputs are not identical.`);
        }
    }
    const modeledResources = input.generatedAccounting.sourceModeledResources;
    const modeledResidentByteLengthIncludingWasmStack = checkedAdd(
        modeledResources.proofGenerationResidentPeakByteLengthExcludingWasmStack,
        wasmStackByteLength,
        'Modeled resident memory including the WASM stack',
    );
    const allMeasurements = [
        ...orderedCommonRows.map((row) => row.measurement),
        evaluatorReplayMeasurement,
    ];
    for (const measurement of allMeasurements) {
        if (
            measurement.wasmMemory.peakByteLength >
                foundationProfile.maximumWasmMemoryByteLength ||
            measurement.boundaryBufferTraffic.maximumBufferByteLength >
                modeledResources.maximumBoundaryCopiedBufferByteLength ||
            measurement.boundaryBufferTraffic.maximumBufferByteLength >
                foundationProfile.maximumCopiedBufferByteLength
        ) {
            throw new Error(`Desktop-browser measurement ${measurement.caseIdentifier} exceeds a source-derived absolute bound.`);
        }
    }
    if (
        evaluatorReplayMeasurement.evaluatorKeyStoreTraffic.declaredByteLength !==
        modeledResources.finalEvaluatorKeyStoreResidentByteLength
    ) {
        throw new Error('Evaluator-replay store bytes do not equal the source-derived final store bytes.');
    }
    const operationRows = orderedCommonRows.map(({ measurement, processMemory }) =>
        Object.freeze({
            boundaryBufferTraffic: measurement.boundaryBufferTraffic,
            canonicalOutputTraffic: measurement.canonicalOutputTraffic,
            caseIdentifier: measurement.caseIdentifier,
            checkpointTraffic: measurement.checkpointTraffic,
            elapsedMilliseconds: measurement.elapsedMilliseconds,
            executionKind: measurement.executionKind,
            externalMemoryTraffic: measurement.externalMemoryTraffic,
            handoffTraffic: measurement.handoffTraffic,
            inputCorpusHash: measurement.measurementIdentity.inputCorpusHash,
            processMemory,
            publicOutputHashes: measurement.publicOutputHashes,
            wasmMemory: measurement.wasmMemory,
        }),
    );
    return Object.freeze({
        desktopBrowserDevelopmentEvidence: Object.freeze({
            commonProofRows: Object.freeze(operationRows),
            evaluatorReplay: Object.freeze({
                boundaryBufferTraffic:
                    evaluatorReplayMeasurement.boundaryBufferTraffic,
                canonicalReplayCarrierTraffic:
                    evaluatorReplayMeasurement.canonicalReplayCarrierTraffic,
                caseIdentifier: evaluatorReplayMeasurement.caseIdentifier,
                elapsedMilliseconds:
                    evaluatorReplayMeasurement.elapsedMilliseconds,
                evaluatorKeyStoreTraffic:
                    evaluatorReplayMeasurement.evaluatorKeyStoreTraffic,
                inputCorpusHash:
                    evaluatorReplayMeasurement.measurementIdentity.inputCorpusHash,
                processMemory: evaluatorReplayProcessMemory,
                publicOutputHashes:
                    evaluatorReplayMeasurement.publicOutputHashes,
                schedulerYieldCount:
                    evaluatorReplayMeasurement.schedulerYieldCount,
                wasmMemory: evaluatorReplayMeasurement.wasmMemory,
            }),
            evidenceScope: 'desktop-chromium-development-measurement',
        }),
        hardResourceAccounting: Object.freeze({
            maximumCanonicalStreamByteLength:
                foundationProfile.maximumCanonicalStreamByteLength,
            maximumCopiedBufferByteLength:
                foundationProfile.maximumCopiedBufferByteLength,
            maximumWasmMemoryByteLength:
                foundationProfile.maximumWasmMemoryByteLength,
            modeledProofGenerationResidentPeakByteLengthExcludingWasmStack:
                modeledResources.proofGenerationResidentPeakByteLengthExcludingWasmStack,
            modeledProofGenerationResidentPeakByteLengthIncludingWasmStack:
                modeledResidentByteLengthIncludingWasmStack,
            wasmStackByteLength,
        }),
        identity: Object.freeze({
            ...input.generatedAccounting.identity,
            manifestHash: referenceIdentity.manifestHash,
            packagedWasmSha256: referenceIdentity.packagedWasmSha256,
            runtimeBuildManifestHash: referenceIdentity.runtimeBuildManifestHash,
        }),
        recordKind: 'selected-complete-action-accounting',
        recordVersion: 1,
        sourceDerivedAccounting: input.generatedAccounting,
    });
};

const parseJsonFile = async (filePath: string): Promise<unknown> => {
    let value: unknown;
    try {
        value = JSON.parse(await readFile(filePath, 'utf8'));
    } catch (error) {
        throw Object.assign(
            new Error(`Could not read exact accounting input ${filePath}.`),
            { cause: error },
        );
    }
    return value;
};

const requireMeasurementDirectoryPath = (rawArguments: readonly string[]): string => {
    const argumentsWithoutSeparator = rawArguments.filter((argument) => argument !== '--');
    if (
        argumentsWithoutSeparator.length !== 2 ||
        argumentsWithoutSeparator[0] !== '--measurement-directory' ||
        argumentsWithoutSeparator[1] === undefined
    ) {
        throw new Error('account:selected-complete-action requires one --measurement-directory argument.');
    }
    const measurementDirectoryPath = path.resolve(argumentsWithoutSeparator[1]);
    const logsDirectoryPath = path.resolve('logs');
    const relativeToLogs = path.relative(logsDirectoryPath, measurementDirectoryPath);
    if (
        path.basename(measurementDirectoryPath) !== 'measurements' ||
        relativeToLogs === '' ||
        relativeToLogs.startsWith('..') ||
        path.isAbsolute(relativeToLogs)
    ) {
        throw new Error('The accounting measurement directory must be one logs run measurement directory.');
    }
    return measurementDirectoryPath;
};

export const runSelectedCompleteActionAccounting = async (): Promise<void> => {
    const measurementDirectoryPath = requireMeasurementDirectoryPath(
        process.argv.slice(2),
    );
    const generatedAccounting =
        validateSelectedCompleteActionGeneratedByteAccounting(
            await parseJsonFile(
                path.join(measurementDirectoryPath, generatedAccountingFileName),
            ),
        );
    const commonProofEvidenceRows = await Promise.all(
        orderedProductionCommonProofMeasurementCases.map(async ({ caseIdentifier }) => ({
            measurement: validateDesktopBrowserCommonProofMeasurement(
                await parseJsonFile(
                    path.join(
                        measurementDirectoryPath,
                        `desktop-browser-common-proof-${caseIdentifier}-measurement.json`,
                    ),
                ),
                caseIdentifier,
            ),
            processMemory: validateDesktopBrowserProcessMemoryMeasurement(
                await parseJsonFile(
                    path.join(
                        measurementDirectoryPath,
                        `desktop-browser-process-memory-${caseIdentifier}.json`,
                    ),
                ),
                caseIdentifier,
            ),
        })),
    );
    const evaluatorReplayCaseIdentifier =
        productionDesktopBrowserEvaluatorReplayMeasurementCaseIdentifier;
    const evaluatorReplayEvidenceRow = Object.freeze({
        measurement: validateDesktopBrowserEvaluatorReplayMeasurement(
            await parseJsonFile(
                path.join(
                    measurementDirectoryPath,
                    `desktop-browser-evaluator-replay-${evaluatorReplayCaseIdentifier}-measurement.json`,
                ),
            ),
            evaluatorReplayCaseIdentifier,
        ),
        processMemory: validateDesktopBrowserProcessMemoryMeasurement(
            await parseJsonFile(
                path.join(
                    measurementDirectoryPath,
                    `desktop-browser-evaluator-replay-process-memory-${evaluatorReplayCaseIdentifier}.json`,
                ),
            ),
            evaluatorReplayCaseIdentifier,
        ),
    });
    const combinedAccounting = assembleSelectedCompleteActionAccounting({
        commonProofEvidenceRows,
        evaluatorReplayEvidenceRow,
        generatedAccounting,
    });
    const outputPath = path.join(
        measurementDirectoryPath,
        combinedAccountingFileName,
    );
    await writeFile(
        outputPath,
        `${JSON.stringify(combinedAccounting, undefined, 2)}\n`,
        { encoding: 'utf8', flag: 'wx' },
    );
    console.info(`Selected complete-action accounting written to ${outputPath}.`);
};

if (import.meta.main) {
    void runSelectedCompleteActionAccounting();
}

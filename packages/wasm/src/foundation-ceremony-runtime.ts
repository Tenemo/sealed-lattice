import { hexToBytes } from '@noble/hashes/utils.js';
import { foundationProfile, type ProtocolHash } from '@sealed-lattice/types';

import {
    bytesToHex,
    textEncoder,
} from './transcript-core-bridge/kernel-contracts.js';
import type {
    FoundationActionContextVerification,
    FoundationActionDefinitionVerification,
    FoundationBoardPolicyVerification,
    FoundationCeremonyContextVerification,
    FoundationManifestVerification,
    FoundationSuiteRecordVerification,
    PublishedSdkKernel,
} from './transcript-core-bridge/kernel-contracts.js';

export type FoundationManifestInput = Readonly<{
    readonly displayTitle: string;
    readonly optionDefinitions: readonly Readonly<{
        readonly displayLabel: string;
        readonly optionIdentifier: string;
        readonly optionIndex: number;
    }>[];
}>;

export type CanonicalFoundationManifest = Readonly<{
    readonly canonicalBytes: Uint8Array;
    readonly manifestHash: ProtocolHash;
}>;

export type CanonicalFoundationActionDefinition = Readonly<{
    readonly actionDefinitionHash: ProtocolHash;
    readonly canonicalBytes: Uint8Array;
}>;

export type CanonicalFoundationBoardPolicy = Readonly<{
    readonly boardPolicyHash: ProtocolHash;
    readonly canonicalBytes: Uint8Array;
}>;

export type FoundationCeremonyRuntime = Readonly<{
    encodeActionDefinition(input: {
        readonly submissionCutoffUnixMilliseconds: bigint;
        readonly topCount: number;
    }): CanonicalFoundationActionDefinition;
    encodeBoardPolicy(input: {
        readonly boardOriginIdentifier: string;
    }): CanonicalFoundationBoardPolicy;
    encodeManifest(input: FoundationManifestInput): CanonicalFoundationManifest;
    verifyActionContext(input: {
        readonly actionIdentifier: string;
        readonly canonicalActionDefinitionBytes: Uint8Array;
        readonly canonicalBoardPolicyBytes: Uint8Array;
        readonly canonicalManifestBytes: Uint8Array;
        readonly canonicalRosterBytes: Uint8Array;
        readonly canonicalSuiteRecordBytes: Uint8Array;
        readonly ceremonyIdentifier: string;
        readonly expectedCeremonyContextHash: ProtocolHash;
        readonly expectedSuiteId: ProtocolHash;
    }): FoundationActionContextVerification;
    verifyActionDefinition(
        canonicalBytes: Uint8Array,
    ): FoundationActionDefinitionVerification;
    verifyBoardPolicy(
        canonicalBytes: Uint8Array,
    ): FoundationBoardPolicyVerification;
    verifyCeremonyContext(input: {
        readonly canonicalManifestBytes: Uint8Array;
        readonly canonicalRosterBytes: Uint8Array;
        readonly canonicalSuiteRecordBytes: Uint8Array;
        readonly ceremonyIdentifier: string;
        readonly expectedSuiteId: ProtocolHash;
    }): FoundationCeremonyContextVerification;
    verifyManifest(canonicalBytes: Uint8Array): FoundationManifestVerification;
    verifySuiteRecord(
        canonicalBytes: Uint8Array,
    ): FoundationSuiteRecordVerification;
}>;

const maximumUnsigned64 = (1n << 64n) - 1n;

const snapshotDataProperty = (
    container: unknown,
    propertyName: string,
    containerName: string,
): unknown => {
    if (
        container === null ||
        (typeof container !== 'object' && typeof container !== 'function')
    ) {
        throw new TypeError(`${containerName} must be an object.`);
    }
    let descriptor: PropertyDescriptor | undefined;
    try {
        descriptor = Object.getOwnPropertyDescriptor(container, propertyName);
    } catch {
        throw new TypeError(
            `${containerName}.${propertyName} must be an ordinary data property.`,
        );
    }
    if (descriptor === undefined || !('value' in descriptor)) {
        throw new TypeError(
            `${containerName}.${propertyName} must be an ordinary data property.`,
        );
    }
    return descriptor.value;
};

const snapshotProtocolHash = (
    value: unknown,
    fieldName: string,
): ProtocolHash => {
    if (typeof value !== 'string') {
        throw new TypeError(`${fieldName} must be a string.`);
    }
    return value;
};

const snapshotSafeInteger = (value: unknown, fieldName: string): number => {
    if (typeof value !== 'number' || !Number.isSafeInteger(value)) {
        throw new TypeError(`${fieldName} must be a safe integer.`);
    }
    return value;
};

const isUint8Array = (value: unknown): value is Uint8Array => {
    try {
        return (
            ArrayBuffer.isView(value) &&
            Object.prototype.toString.call(value) === '[object Uint8Array]'
        );
    } catch {
        return false;
    }
};

const copyCanonicalBytes = (value: unknown, fieldName: string): Uint8Array => {
    if (!isUint8Array(value)) {
        throw new TypeError(`${fieldName} must be a Uint8Array.`);
    }
    try {
        return Uint8Array.from(value);
    } catch {
        throw new TypeError(
            `${fieldName} must reference an attached Uint8Array.`,
        );
    }
};

const isWellFormedString = (value: string): boolean => {
    for (
        let codeUnitIndex = 0;
        codeUnitIndex < value.length;
        codeUnitIndex += 1
    ) {
        const codeUnit = value.charCodeAt(codeUnitIndex);
        if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
            const followingCodeUnit = value.charCodeAt(codeUnitIndex + 1);
            if (
                codeUnitIndex + 1 >= value.length ||
                followingCodeUnit < 0xdc00 ||
                followingCodeUnit > 0xdfff
            ) {
                return false;
            }
            codeUnitIndex += 1;
        } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
            return false;
        }
    }
    return true;
};

const requireWellFormedString = (value: unknown, fieldName: string): string => {
    if (typeof value !== 'string' || !isWellFormedString(value)) {
        throw new TypeError(`${fieldName} must be a well-formed string.`);
    }
    return value;
};

const canonicalBytesHex = (value: unknown, fieldName: string): string =>
    bytesToHex(copyCanonicalBytes(value, fieldName));

const displayTextHex = (value: string, fieldName: string): string =>
    bytesToHex(textEncoder.encode(requireWellFormedString(value, fieldName)));

const decodeCanonicalOutput = (value: string): Uint8Array =>
    Uint8Array.from(hexToBytes(value));

const snapshotManifestInput = (input: unknown): FoundationManifestInput => {
    const displayTitle = requireWellFormedString(
        snapshotDataProperty(input, 'displayTitle', 'input'),
        'displayTitle',
    );
    const optionDefinitionsValue = snapshotDataProperty(
        input,
        'optionDefinitions',
        'input',
    );
    if (!Array.isArray(optionDefinitionsValue)) {
        throw new TypeError('optionDefinitions must be an array.');
    }
    const optionDefinitionCount = snapshotSafeInteger(
        snapshotDataProperty(
            optionDefinitionsValue,
            'length',
            'optionDefinitions',
        ),
        'optionDefinitions.length',
    );
    if (optionDefinitionCount !== foundationProfile.optionCount) {
        throw new RangeError(
            `optionDefinitions must contain exactly ${String(foundationProfile.optionCount)} entries.`,
        );
    }
    const optionDefinitions = Array.from(
        { length: optionDefinitionCount },
        (_unused, optionPosition) => {
            const optionName = `optionDefinitions[${String(optionPosition)}]`;
            const optionDefinition = snapshotDataProperty(
                optionDefinitionsValue,
                String(optionPosition),
                'optionDefinitions',
            );
            return Object.freeze({
                displayLabel: requireWellFormedString(
                    snapshotDataProperty(
                        optionDefinition,
                        'displayLabel',
                        optionName,
                    ),
                    `${optionName}.displayLabel`,
                ),
                optionIdentifier: requireWellFormedString(
                    snapshotDataProperty(
                        optionDefinition,
                        'optionIdentifier',
                        optionName,
                    ),
                    `${optionName}.optionIdentifier`,
                ),
                optionIndex: snapshotSafeInteger(
                    snapshotDataProperty(
                        optionDefinition,
                        'optionIndex',
                        optionName,
                    ),
                    `${optionName}.optionIndex`,
                ),
            });
        },
    );
    return Object.freeze({ displayTitle, optionDefinitions });
};

/** Opens the typed byte boundary backed by one already loaded Rust/WASM kernel. */
export const openFoundationCeremonyRuntime = (
    kernel: PublishedSdkKernel,
): FoundationCeremonyRuntime => ({
    encodeActionDefinition: (input) => {
        const submissionCutoffUnixMilliseconds = snapshotDataProperty(
            input,
            'submissionCutoffUnixMilliseconds',
            'input',
        );
        const topCount = snapshotSafeInteger(
            snapshotDataProperty(input, 'topCount', 'input'),
            'topCount',
        );
        if (
            typeof submissionCutoffUnixMilliseconds !== 'bigint' ||
            submissionCutoffUnixMilliseconds < 0n ||
            submissionCutoffUnixMilliseconds > maximumUnsigned64
        ) {
            throw new RangeError(
                'submissionCutoffUnixMilliseconds must fit an unsigned 64-bit integer.',
            );
        }
        const encoded = kernel.encodeFoundationActionDefinition({
            submissionCutoffUnixMilliseconds:
                submissionCutoffUnixMilliseconds.toString(10),
            topCount,
        });
        return Object.freeze({
            actionDefinitionHash: encoded.actionDefinitionHash,
            canonicalBytes: decodeCanonicalOutput(encoded.canonicalBytesHex),
        });
    },
    encodeBoardPolicy: (input) => {
        const boardOriginIdentifier = requireWellFormedString(
            snapshotDataProperty(input, 'boardOriginIdentifier', 'input'),
            'boardOriginIdentifier',
        );
        const encoded = kernel.encodeFoundationBoardPolicy({
            boardOriginIdentifier,
        });
        return Object.freeze({
            boardPolicyHash: encoded.boardPolicyHash,
            canonicalBytes: decodeCanonicalOutput(encoded.canonicalBytesHex),
        });
    },
    encodeManifest: (input) => {
        const snapshot = snapshotManifestInput(input);
        const encoded = kernel.encodeFoundationManifest({
            displayTitleUtf8Hex: displayTextHex(
                snapshot.displayTitle,
                'displayTitle',
            ),
            optionDefinitions: snapshot.optionDefinitions.map(
                (optionDefinition, optionPosition) => ({
                    displayLabelUtf8Hex: displayTextHex(
                        optionDefinition.displayLabel,
                        `optionDefinitions[${String(optionPosition)}].displayLabel`,
                    ),
                    optionIdentifier: requireWellFormedString(
                        optionDefinition.optionIdentifier,
                        `optionDefinitions[${String(optionPosition)}].optionIdentifier`,
                    ),
                    optionIndex: optionDefinition.optionIndex,
                }),
            ),
        });
        return Object.freeze({
            canonicalBytes: decodeCanonicalOutput(encoded.canonicalBytesHex),
            manifestHash: encoded.manifestHash,
        });
    },
    verifyActionContext: (input) => {
        const actionIdentifier = requireWellFormedString(
            snapshotDataProperty(input, 'actionIdentifier', 'input'),
            'actionIdentifier',
        );
        const canonicalActionDefinitionBytesHex = canonicalBytesHex(
            snapshotDataProperty(
                input,
                'canonicalActionDefinitionBytes',
                'input',
            ),
            'canonicalActionDefinitionBytes',
        );
        const canonicalBoardPolicyBytesHex = canonicalBytesHex(
            snapshotDataProperty(input, 'canonicalBoardPolicyBytes', 'input'),
            'canonicalBoardPolicyBytes',
        );
        const canonicalManifestBytesHex = canonicalBytesHex(
            snapshotDataProperty(input, 'canonicalManifestBytes', 'input'),
            'canonicalManifestBytes',
        );
        const canonicalRosterBytesHex = canonicalBytesHex(
            snapshotDataProperty(input, 'canonicalRosterBytes', 'input'),
            'canonicalRosterBytes',
        );
        const canonicalSuiteRecordBytesHex = canonicalBytesHex(
            snapshotDataProperty(input, 'canonicalSuiteRecordBytes', 'input'),
            'canonicalSuiteRecordBytes',
        );
        const ceremonyIdentifier = requireWellFormedString(
            snapshotDataProperty(input, 'ceremonyIdentifier', 'input'),
            'ceremonyIdentifier',
        );
        const expectedCeremonyContextHash = snapshotProtocolHash(
            snapshotDataProperty(input, 'expectedCeremonyContextHash', 'input'),
            'expectedCeremonyContextHash',
        );
        const expectedSuiteId = snapshotProtocolHash(
            snapshotDataProperty(input, 'expectedSuiteId', 'input'),
            'expectedSuiteId',
        );
        return kernel.verifyFoundationActionContext({
            actionIdentifier,
            canonicalActionDefinitionBytesHex,
            canonicalBoardPolicyBytesHex,
            canonicalManifestBytesHex,
            canonicalRosterBytesHex,
            canonicalSuiteRecordBytesHex,
            ceremonyIdentifier,
            expectedCeremonyContextHash,
            expectedSuiteId,
        });
    },
    verifyActionDefinition: (canonicalBytes) =>
        kernel.verifyFoundationActionDefinition({
            canonicalBytesHex: canonicalBytesHex(
                canonicalBytes,
                'canonicalBytes',
            ),
        }),
    verifyBoardPolicy: (canonicalBytes) =>
        kernel.verifyFoundationBoardPolicy({
            canonicalBytesHex: canonicalBytesHex(
                canonicalBytes,
                'canonicalBytes',
            ),
        }),
    verifyCeremonyContext: (input) => {
        const canonicalManifestBytesHex = canonicalBytesHex(
            snapshotDataProperty(input, 'canonicalManifestBytes', 'input'),
            'canonicalManifestBytes',
        );
        const canonicalRosterBytesHex = canonicalBytesHex(
            snapshotDataProperty(input, 'canonicalRosterBytes', 'input'),
            'canonicalRosterBytes',
        );
        const canonicalSuiteRecordBytesHex = canonicalBytesHex(
            snapshotDataProperty(input, 'canonicalSuiteRecordBytes', 'input'),
            'canonicalSuiteRecordBytes',
        );
        const ceremonyIdentifier = requireWellFormedString(
            snapshotDataProperty(input, 'ceremonyIdentifier', 'input'),
            'ceremonyIdentifier',
        );
        const expectedSuiteId = snapshotProtocolHash(
            snapshotDataProperty(input, 'expectedSuiteId', 'input'),
            'expectedSuiteId',
        );
        return kernel.verifyFoundationCeremonyContext({
            canonicalManifestBytesHex,
            canonicalRosterBytesHex,
            canonicalSuiteRecordBytesHex,
            ceremonyIdentifier,
            expectedSuiteId,
        });
    },
    verifyManifest: (canonicalBytes) =>
        kernel.verifyFoundationManifest({
            canonicalBytesHex: canonicalBytesHex(
                canonicalBytes,
                'canonicalBytes',
            ),
        }),
    verifySuiteRecord: (canonicalBytes) =>
        kernel.verifyFoundationSuiteRecord({
            canonicalBytesHex: canonicalBytesHex(
                canonicalBytes,
                'canonicalBytes',
            ),
        }),
});

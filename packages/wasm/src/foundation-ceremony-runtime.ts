import { hexToBytes } from '@noble/hashes/utils.js';
import type { ProtocolHash } from '@sealed-lattice/types';

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

const requireWellFormedString = (value: string, fieldName: string): string => {
    if (typeof value !== 'string' || !isWellFormedString(value)) {
        throw new TypeError(`${fieldName} must be a well-formed string.`);
    }
    return value;
};

const canonicalBytesHex = (value: Uint8Array): string =>
    bytesToHex(Uint8Array.from(value));

const displayTextHex = (value: string, fieldName: string): string =>
    bytesToHex(textEncoder.encode(requireWellFormedString(value, fieldName)));

const decodeCanonicalOutput = (value: string): Uint8Array =>
    Uint8Array.from(hexToBytes(value));

/** Opens the typed byte boundary backed by one already loaded Rust/WASM kernel. */
export const openFoundationCeremonyRuntime = (
    kernel: PublishedSdkKernel,
): FoundationCeremonyRuntime => ({
    encodeActionDefinition: (input) => {
        if (
            typeof input.submissionCutoffUnixMilliseconds !== 'bigint' ||
            input.submissionCutoffUnixMilliseconds < 0n ||
            input.submissionCutoffUnixMilliseconds > maximumUnsigned64
        ) {
            throw new RangeError(
                'submissionCutoffUnixMilliseconds must fit an unsigned 64-bit integer.',
            );
        }
        const encoded = kernel.encodeFoundationActionDefinition({
            submissionCutoffUnixMilliseconds:
                input.submissionCutoffUnixMilliseconds.toString(10),
            topCount: input.topCount,
        });
        return Object.freeze({
            actionDefinitionHash: encoded.actionDefinitionHash,
            canonicalBytes: decodeCanonicalOutput(encoded.canonicalBytesHex),
        });
    },
    encodeBoardPolicy: (input) => {
        const encoded = kernel.encodeFoundationBoardPolicy({
            boardOriginIdentifier: requireWellFormedString(
                input.boardOriginIdentifier,
                'boardOriginIdentifier',
            ),
        });
        return Object.freeze({
            boardPolicyHash: encoded.boardPolicyHash,
            canonicalBytes: decodeCanonicalOutput(encoded.canonicalBytesHex),
        });
    },
    encodeManifest: (input) => {
        const encoded = kernel.encodeFoundationManifest({
            displayTitleUtf8Hex: displayTextHex(
                input.displayTitle,
                'displayTitle',
            ),
            optionDefinitions: input.optionDefinitions.map(
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
    verifyActionContext: (input) =>
        kernel.verifyFoundationActionContext({
            actionIdentifier: requireWellFormedString(
                input.actionIdentifier,
                'actionIdentifier',
            ),
            canonicalActionDefinitionBytesHex: canonicalBytesHex(
                input.canonicalActionDefinitionBytes,
            ),
            canonicalBoardPolicyBytesHex: canonicalBytesHex(
                input.canonicalBoardPolicyBytes,
            ),
            canonicalManifestBytesHex: canonicalBytesHex(
                input.canonicalManifestBytes,
            ),
            canonicalRosterBytesHex: canonicalBytesHex(
                input.canonicalRosterBytes,
            ),
            canonicalSuiteRecordBytesHex: canonicalBytesHex(
                input.canonicalSuiteRecordBytes,
            ),
            ceremonyIdentifier: requireWellFormedString(
                input.ceremonyIdentifier,
                'ceremonyIdentifier',
            ),
            expectedCeremonyContextHash: input.expectedCeremonyContextHash,
            expectedSuiteId: input.expectedSuiteId,
        }),
    verifyActionDefinition: (canonicalBytes) =>
        kernel.verifyFoundationActionDefinition({
            canonicalBytesHex: canonicalBytesHex(canonicalBytes),
        }),
    verifyBoardPolicy: (canonicalBytes) =>
        kernel.verifyFoundationBoardPolicy({
            canonicalBytesHex: canonicalBytesHex(canonicalBytes),
        }),
    verifyCeremonyContext: (input) =>
        kernel.verifyFoundationCeremonyContext({
            canonicalManifestBytesHex: canonicalBytesHex(
                input.canonicalManifestBytes,
            ),
            canonicalRosterBytesHex: canonicalBytesHex(
                input.canonicalRosterBytes,
            ),
            canonicalSuiteRecordBytesHex: canonicalBytesHex(
                input.canonicalSuiteRecordBytes,
            ),
            ceremonyIdentifier: requireWellFormedString(
                input.ceremonyIdentifier,
                'ceremonyIdentifier',
            ),
            expectedSuiteId: input.expectedSuiteId,
        }),
    verifyManifest: (canonicalBytes) =>
        kernel.verifyFoundationManifest({
            canonicalBytesHex: canonicalBytesHex(canonicalBytes),
        }),
    verifySuiteRecord: (canonicalBytes) =>
        kernel.verifyFoundationSuiteRecord({
            canonicalBytesHex: canonicalBytesHex(canonicalBytes),
        }),
});

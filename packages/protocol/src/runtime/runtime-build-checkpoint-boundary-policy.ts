import {
    decodeCommonProofCheckpointCursorManifest,
    isAssignedRuntimeCheckpointRandomUse,
    isPublicOnlyCommonProofCheckpointFamily,
    type DecodedCommonProofCheckpointCursorManifest,
    type RuntimeBuildManifest,
} from '@sealed-lattice/wasm';

import type {
    CheckpointBoundary,
    CheckpointBoundaryPolicy,
    ExpectedCheckpointBoundary,
} from './authenticated-checkpoint-store.js';

const privateRandomnessStreamAttemptIdentifierByteLength = 32;
const derivationBindingHashByteLength = 64;
const maximumUnsigned16 = 0xffff;
const maximumUnsigned32 = 0xffff_ffff;
const maximumStateStreamDomainByteLength = 256;
const textEncoder = new TextEncoder();

export class RuntimeBuildCheckpointBoundaryPolicyError extends Error {
    public readonly cause: unknown;

    public constructor(message: string, cause?: unknown) {
        super(message);
        this.cause = cause;
        this.name = 'RuntimeBuildCheckpointBoundaryPolicyError';
    }
}

/**
 * The canonical state stream domain is supplied explicitly by the state-codec
 * integration. The runtime manifest binds its numeric state schema but
 * deliberately does not duplicate that domain string.
 */
export type RuntimeBuildCheckpointBoundaryBinding = Readonly<{
    safeBoundaryOrdinal: number;
    stateSchemaIdentifier: number;
    stateStreamDomain: string;
}>;

export type RuntimeBuildCheckpointBoundaryPolicyInput = Readonly<{
    operationKind: number;
    orderedBoundaryBindings: readonly RuntimeBuildCheckpointBoundaryBinding[];
    runtimeBuildManifest: RuntimeBuildManifest;
}>;

type ValidatedRandomUse = Readonly<{
    family: number;
    purpose: number;
}>;

type ValidatedBoundaryProfile = Readonly<{
    orderedRandomUses: readonly ValidatedRandomUse[];
    safeBoundaryOrdinal: number;
    stateSchemaIdentifier: number;
    stateStreamDomain: string;
}>;

type ValidatedManifestBoundaryProfile = Readonly<{
    orderedRandomUses: readonly ValidatedRandomUse[];
    stateSchemaIdentifier: number;
}>;

type ValidatedOperationProfile = Readonly<{
    operationKind: number;
    safeBoundaries: readonly ValidatedManifestBoundaryProfile[];
}>;

const fail = (message: string): never => {
    throw new RuntimeBuildCheckpointBoundaryPolicyError(message);
};

const isRecord = (value: unknown): value is Record<string, unknown> =>
    typeof value === 'object' && value !== null;

const requireUnsigned16 = (value: unknown, label: string): number => {
    if (
        typeof value !== 'number' ||
        !Number.isInteger(value) ||
        value <= 0 ||
        value > maximumUnsigned16
    ) {
        return fail(`${label} is outside the assigned unsigned-16 profile.`);
    }
    return value;
};

const requireSafeBoundaryOrdinal = (value: unknown, label: string): number => {
    if (
        typeof value !== 'number' ||
        !Number.isInteger(value) ||
        value < 0 ||
        value > maximumUnsigned32
    ) {
        return fail(`${label} is outside the unsigned-32 profile.`);
    }
    return value;
};

const requireStateStreamDomain = (value: unknown): string => {
    if (typeof value !== 'string') {
        return fail(
            'A checkpoint boundary binding lacks a state stream domain.',
        );
    }
    const encoded = textEncoder.encode(value);
    if (
        encoded.byteLength === 0 ||
        encoded.byteLength > maximumStateStreamDomainByteLength ||
        !encoded.every((byte) => byte >= 0x20 && byte <= 0x7e)
    ) {
        return fail(
            'A checkpoint boundary binding has a non-canonical state stream domain.',
        );
    }
    return value;
};

const compareRandomUse = (
    left: ValidatedRandomUse,
    right: ValidatedRandomUse,
): number => left.family - right.family || left.purpose - right.purpose;

const validateRandomUses = (
    value: unknown,
    operationKind: number,
    boundaryIndex: number,
): readonly ValidatedRandomUse[] => {
    if (!Array.isArray(value)) {
        return fail(
            `Runtime operation ${operationKind} boundary ${boundaryIndex} lacks an ordered random-use profile.`,
        );
    }
    const copied: ValidatedRandomUse[] = [];
    for (
        let randomUseIndex = 0;
        randomUseIndex < value.length;
        randomUseIndex += 1
    ) {
        const randomUse = value[randomUseIndex] as unknown;
        if (!isRecord(randomUse)) {
            return fail(
                `Runtime operation ${operationKind} boundary ${boundaryIndex} has a malformed random-use profile.`,
            );
        }
        const family = requireUnsigned16(
            randomUse.family,
            'A checkpoint random-use family',
        );
        const purpose = requireUnsigned16(
            randomUse.purpose,
            'A checkpoint random-use purpose',
        );
        if (!isAssignedRuntimeCheckpointRandomUse(family, purpose)) {
            return fail(
                `Runtime operation ${operationKind} boundary ${boundaryIndex} names an unassigned random-use profile.`,
            );
        }
        const copiedRandomUse = Object.freeze({ family, purpose });
        const previous = copied[copied.length - 1];
        if (
            previous !== undefined &&
            compareRandomUse(previous, copiedRandomUse) >= 0
        ) {
            return fail(
                `Runtime operation ${operationKind} boundary ${boundaryIndex} random uses are duplicated or unsorted.`,
            );
        }
        copied.push(copiedRandomUse);
    }
    return Object.freeze(copied);
};

const validateBoundaryProfiles = (
    value: unknown,
    operationKind: number,
): readonly ValidatedManifestBoundaryProfile[] => {
    if (!Array.isArray(value) || value.length === 0) {
        return fail(
            `Runtime operation ${operationKind} has no checkpoint boundaries.`,
        );
    }
    return Object.freeze(
        value.map((candidate: unknown, boundaryIndex: number) => {
            if (!isRecord(candidate)) {
                return fail(
                    `Runtime operation ${operationKind} boundary ${boundaryIndex} is malformed.`,
                );
            }
            const stateSchemaIdentifier = requireUnsigned16(
                candidate.stateSchemaIdentifier,
                `Runtime operation ${operationKind} boundary ${boundaryIndex} state schema`,
            );
            const orderedRandomUses = validateRandomUses(
                candidate.orderedRandomUses,
                operationKind,
                boundaryIndex,
            );
            return Object.freeze({
                orderedRandomUses,
                stateSchemaIdentifier,
            });
        }),
    );
};

const selectOperationProfile = (
    operationProfilesValue: unknown,
    selectedOperationKindValue: unknown,
): ValidatedOperationProfile => {
    const selectedOperationKind = requireUnsigned16(
        selectedOperationKindValue,
        'The selected checkpoint operation kind',
    );
    if (!Array.isArray(operationProfilesValue)) {
        return fail(
            'The runtime build lacks an ordered operation profile list.',
        );
    }
    let previousOperationKind = 0;
    let selectedProfile: ValidatedOperationProfile | undefined;
    for (
        let profileIndex = 0;
        profileIndex < operationProfilesValue.length;
        profileIndex += 1
    ) {
        const candidate = operationProfilesValue[profileIndex] as unknown;
        if (!isRecord(candidate)) {
            return fail(
                `Runtime operation profile ${profileIndex} is malformed.`,
            );
        }
        const operationKind = requireUnsigned16(
            candidate.operationKind,
            `Runtime operation profile ${profileIndex} kind`,
        );
        if (operationKind <= previousOperationKind) {
            return fail(
                'Runtime operation profiles are duplicated or unsorted.',
            );
        }
        previousOperationKind = operationKind;
        const safeBoundaries = validateBoundaryProfiles(
            candidate.safeBoundaries,
            operationKind,
        );
        if (operationKind === selectedOperationKind) {
            selectedProfile = Object.freeze({
                operationKind,
                safeBoundaries,
            });
        }
    }
    if (selectedProfile === undefined) {
        return fail(
            `Runtime operation ${selectedOperationKind} has no checkpoint profile.`,
        );
    }
    return selectedProfile;
};

const copyExactBoundaryProfiles = (
    operationProfile: ValidatedOperationProfile,
    orderedBoundaryBindingsValue: unknown,
): readonly ValidatedBoundaryProfile[] => {
    if (!Array.isArray(orderedBoundaryBindingsValue)) {
        return fail(
            `Runtime operation ${operationProfile.operationKind} lacks canonical state stream-domain bindings.`,
        );
    }
    if (
        orderedBoundaryBindingsValue.length !==
        operationProfile.safeBoundaries.length
    ) {
        return fail(
            `Runtime operation ${operationProfile.operationKind} does not have one exact binding for every checkpoint boundary.`,
        );
    }
    const copied: ValidatedBoundaryProfile[] = [];
    for (
        let boundaryIndex = 0;
        boundaryIndex < operationProfile.safeBoundaries.length;
        boundaryIndex += 1
    ) {
        const profile = operationProfile.safeBoundaries[boundaryIndex];
        const binding = orderedBoundaryBindingsValue[boundaryIndex] as unknown;
        if (profile === undefined || !isRecord(binding)) {
            return fail(
                `Runtime operation ${operationProfile.operationKind} boundary ${boundaryIndex} lacks its exact binding.`,
            );
        }
        const safeBoundaryOrdinal = requireSafeBoundaryOrdinal(
            binding.safeBoundaryOrdinal,
            `Runtime operation ${operationProfile.operationKind} boundary ${boundaryIndex} ordinal`,
        );
        if (safeBoundaryOrdinal !== boundaryIndex) {
            return fail(
                `Runtime operation ${operationProfile.operationKind} boundary ordinals must be contiguous, duplicate-free, and ordered from zero.`,
            );
        }
        const stateSchemaIdentifier = requireUnsigned16(
            binding.stateSchemaIdentifier,
            `Runtime operation ${operationProfile.operationKind} boundary ${boundaryIndex} bound state schema`,
        );
        if (stateSchemaIdentifier !== profile.stateSchemaIdentifier) {
            return fail(
                `Runtime operation ${operationProfile.operationKind} boundary ${safeBoundaryOrdinal} has the wrong state schema binding.`,
            );
        }
        const orderedRandomUses = profile.orderedRandomUses.map((randomUse) =>
            Object.freeze({
                family: randomUse.family,
                purpose: randomUse.purpose,
            }),
        );
        if (
            isPublicOnlyCommonProofCheckpointFamily(
                operationProfile.operationKind,
            ) &&
            orderedRandomUses.length !== 0
        ) {
            return fail(
                `Public-only runtime operation ${operationProfile.operationKind} boundary ${safeBoundaryOrdinal} assigns a private-randomness cursor use.`,
            );
        }
        if (
            orderedRandomUses.some(
                (randomUse) =>
                    randomUse.family !== orderedRandomUses[0]?.family,
            )
        ) {
            return fail(
                `Runtime operation ${operationProfile.operationKind} boundary ${safeBoundaryOrdinal} spans multiple cursor families.`,
            );
        }
        copied.push(
            Object.freeze({
                orderedRandomUses: Object.freeze(orderedRandomUses),
                safeBoundaryOrdinal,
                stateSchemaIdentifier,
                stateStreamDomain: requireStateStreamDomain(
                    binding.stateStreamDomain,
                ),
            }),
        );
    }
    return Object.freeze(copied);
};

const bytesEqual = (left: Uint8Array, right: Uint8Array): boolean => {
    if (left.byteLength !== right.byteLength) {
        return false;
    }
    let difference = 0;
    for (let byteIndex = 0; byteIndex < left.byteLength; byteIndex += 1) {
        difference |= (left[byteIndex] ?? 0) ^ (right[byteIndex] ?? 0);
    }
    return difference === 0;
};

type IdentityBearingCheckpointCursorManifest = Extract<
    DecodedCommonProofCheckpointCursorManifest,
    { hasPrivateRandomnessIdentity: true }
>;

const validateCursorIdentityBindings = (
    boundary: CheckpointBoundary | ExpectedCheckpointBoundary,
    decoded: IdentityBearingCheckpointCursorManifest,
): void => {
    const commonProofRuntimeBindingHash = boundary.orderedSourceDigests[0];
    const stableAttemptBindingHash = boundary.orderedSourceDigests[1];
    if (
        !(commonProofRuntimeBindingHash instanceof Uint8Array) ||
        commonProofRuntimeBindingHash.byteLength !==
            derivationBindingHashByteLength ||
        !(stableAttemptBindingHash instanceof Uint8Array) ||
        stableAttemptBindingHash.byteLength !==
            derivationBindingHashByteLength ||
        !bytesEqual(
            commonProofRuntimeBindingHash,
            decoded.derivationBindingHash,
        ) ||
        !bytesEqual(stableAttemptBindingHash, decoded.derivationBindingHash)
    ) {
        return fail(
            'A checkpoint boundary does not bind its runtime and cursor derivation identities to the same proof authorization.',
        );
    }
    if (
        !(
            boundary.privateRandomnessStreamAttemptIdentifier instanceof
            Uint8Array
        ) ||
        boundary.privateRandomnessStreamAttemptIdentifier.byteLength !==
            privateRandomnessStreamAttemptIdentifierByteLength ||
        !bytesEqual(
            boundary.privateRandomnessStreamAttemptIdentifier,
            decoded.privateRandomnessStreamAttemptIdentifier,
        )
    ) {
        return fail(
            'A checkpoint boundary does not bind its cursor stream-attempt identifier.',
        );
    }
};

const validateCursorProfile = (
    boundary: CheckpointBoundary | ExpectedCheckpointBoundary,
    expectedProfile: ValidatedBoundaryProfile,
): void => {
    let decoded;
    try {
        decoded = decodeCommonProofCheckpointCursorManifest(
            boundary.privateRandomCursorManifestBytes,
        );
    } catch (error) {
        throw new RuntimeBuildCheckpointBoundaryPolicyError(
            'A checkpoint cursor manifest is not canonical.',
            error,
        );
    }
    if (expectedProfile.orderedRandomUses.length === 0) {
        if (isPublicOnlyCommonProofCheckpointFamily(boundary.operationKind)) {
            if (
                !decoded.hasPrivateRandomnessIdentity ||
                decoded.familySchemaIdentifier !== boundary.operationKind ||
                decoded.orderedPurposeClasses.length !== 0
            ) {
                return fail(
                    'A public-only checkpoint cursor manifest does not bind its exact operation family with zero private-randomness purposes.',
                );
            }
            validateCursorIdentityBindings(boundary, decoded);
            return;
        }
        if (
            decoded.hasPrivateRandomnessIdentity ||
            boundary.privateRandomnessStreamAttemptIdentifier !== undefined
        ) {
            return fail(
                'A deterministic checkpoint boundary contains a private-randomness cursor identity.',
            );
        }
        return;
    }
    const expectedFamily = expectedProfile.orderedRandomUses[0]?.family;
    const expectedPurposeClasses = new Set(
        expectedProfile.orderedRandomUses.map((randomUse) => randomUse.purpose),
    );
    // The identity is present before the first cursor is consumed, while the
    // cursor manifest lists only purposes that have materialized. Exact live
    // cursor completeness belongs to canonical state resumption, which this
    // metadata policy cannot inspect.
    if (
        expectedFamily === undefined ||
        !decoded.hasPrivateRandomnessIdentity ||
        decoded.familySchemaIdentifier !== expectedFamily ||
        decoded.orderedPurposeClasses.some(
            (purpose) => !expectedPurposeClasses.has(purpose),
        )
    ) {
        return fail(
            'A checkpoint cursor manifest does not match its runtime random-use profile.',
        );
    }
    validateCursorIdentityBindings(boundary, decoded);
};

export const createRuntimeBuildCheckpointBoundaryPolicy = (
    input: RuntimeBuildCheckpointBoundaryPolicyInput,
): CheckpointBoundaryPolicy => {
    if (!isRecord(input) || !isRecord(input.runtimeBuildManifest)) {
        return fail('A runtime checkpoint policy input is malformed.');
    }
    const operationProfile = selectOperationProfile(
        input.runtimeBuildManifest.operationProfiles,
        input.operationKind,
    );
    const boundaryProfiles = copyExactBoundaryProfiles(
        operationProfile,
        input.orderedBoundaryBindings,
    );
    const boundaryProfilesByOrdinal = new Map(
        boundaryProfiles.map((profile) => [
            profile.safeBoundaryOrdinal,
            profile,
        ]),
    );

    const validateBoundary = (
        boundary: CheckpointBoundary | ExpectedCheckpointBoundary,
    ): void => {
        if (!isRecord(boundary)) {
            return fail('A checkpoint boundary is malformed.');
        }
        if (boundary.operationKind !== operationProfile.operationKind) {
            return fail(
                `A checkpoint boundary names operation ${String(boundary.operationKind)} instead of ${operationProfile.operationKind}.`,
            );
        }
        const expectedProfile = boundaryProfilesByOrdinal.get(
            boundary.safeBoundaryOrdinal,
        );
        if (expectedProfile === undefined) {
            return fail(
                `Runtime operation ${operationProfile.operationKind} does not assign checkpoint boundary ${String(boundary.safeBoundaryOrdinal)}.`,
            );
        }
        if (boundary.stateStreamDomain !== expectedProfile.stateStreamDomain) {
            return fail(
                `Runtime operation ${operationProfile.operationKind} checkpoint boundary ${expectedProfile.safeBoundaryOrdinal} has the wrong state stream domain for schema ${expectedProfile.stateSchemaIdentifier}.`,
            );
        }
        validateCursorProfile(boundary, expectedProfile);
    };

    return Object.freeze({
        validatePublication: ({ boundary, previousBoundary }) => {
            if (previousBoundary !== undefined) {
                validateBoundary(previousBoundary);
            }
            validateBoundary(boundary);
        },
        validateResume: ({ expectedBoundary }) => {
            validateBoundary(expectedBoundary);
        },
    }) satisfies CheckpointBoundaryPolicy;
};

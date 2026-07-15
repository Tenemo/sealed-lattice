import type { RefusalReason, VerificationResult } from '@sealed-lattice/types';

const hashByteLength = 64;
const checkpointVersion = 1;
const maximumUnsigned64 = 0xffff_ffff_ffff_ffffn;

export type NamespaceFreshnessContext = Readonly<{
    actionContextHash: Uint8Array;
    ceremonyContextHash: Uint8Array;
    storageInstanceIdentity: Uint8Array;
    subjectParticipantIdentity: Uint8Array;
    suiteIdentifier: Uint8Array;
}>;

export type NamespaceFreshnessCheckpointDescription =
    NamespaceFreshnessContext &
        Readonly<{
            authenticatedHeadDigest: Uint8Array;
            checkpointHash: Uint8Array;
            namespaceSequence: bigint;
            previousCheckpointHash?: Uint8Array;
            version: typeof checkpointVersion;
        }>;

declare const verifiedNamespaceFreshnessCheckpointBrand: unique symbol;
declare const verifiedNamespaceFreshnessCertificateBrand: unique symbol;
declare const namespaceFreshnessActiveCapabilityBrand: unique symbol;

export type VerifiedNamespaceFreshnessCheckpoint = Readonly<{
    readonly [verifiedNamespaceFreshnessCheckpointBrand]: true;
}>;

export type VerifiedNamespaceFreshnessCertificate = Readonly<{
    readonly [verifiedNamespaceFreshnessCertificateBrand]: true;
}>;

export type NamespaceFreshnessActiveCapability = Readonly<{
    readonly [namespaceFreshnessActiveCapabilityBrand]: true;
}>;

export type UntrustedNamespaceFreshnessCertificate = Readonly<{
    canonicalCheckpoint: Uint8Array;
    untrustedVoteCarriers: readonly Uint8Array[];
}>;

export type NamespaceFreshnessPreparedCheckpoint = Readonly<{
    canonicalCheckpoint: Uint8Array;
    description: NamespaceFreshnessCheckpointDescription;
    verifiedCheckpoint: VerifiedNamespaceFreshnessCheckpoint;
}>;

export type NamespaceFreshnessVerifiedCertificate = Readonly<{
    description: NamespaceFreshnessCheckpointDescription;
    verifiedCertificate: VerifiedNamespaceFreshnessCertificate;
    verifiedWitnessIdentities: readonly Uint8Array[];
}>;

/**
 * Cryptographic and canonical boundary. Its implementation must be backed by
 * the participant's verifier kernel: it recomputes checkpoint hashes, verifies
 * every supplied carrier, rejects duplicate/out-of-order/non-roster witnesses,
 * and returns capabilities that cannot be reconstructed from descriptions.
 */
export type NamespaceFreshnessVerifier = Readonly<{
    prepareCheckpoint(input: {
        context: NamespaceFreshnessContext;
        authenticatedHeadDigest: Uint8Array;
        namespaceSequence: bigint;
        previousCheckpointHash?: Uint8Array;
    }): VerificationResult<NamespaceFreshnessPreparedCheckpoint>;
    verifyCheckpoint(input: {
        canonicalCheckpoint: Uint8Array;
        expectedContext: NamespaceFreshnessContext;
    }): VerificationResult<NamespaceFreshnessPreparedCheckpoint>;
    verifyVoteCarrier(input: {
        expectedWitnessParticipantIdentity: Uint8Array;
        untrustedVoteCarrier: Uint8Array;
        verifiedCheckpoint: VerifiedNamespaceFreshnessCheckpoint;
    }): VerificationResult<undefined>;
    verifyCertificate(input: {
        canonicalCheckpoint: Uint8Array;
        expectedContext: NamespaceFreshnessContext;
        externalRosterWitnessIdentities: readonly Uint8Array[];
        freshnessQuorum: number;
        untrustedVoteCarriers: readonly Uint8Array[];
    }): VerificationResult<NamespaceFreshnessVerifiedCertificate>;
}>;

export type NamespaceFreshnessClosedWitnessSigner = Readonly<{
    signVerifiedCheckpoint(input: {
        verifiedCheckpoint: VerifiedNamespaceFreshnessCheckpoint;
        witnessParticipantIdentity: Uint8Array;
    }): Promise<Uint8Array>;
}>;

export type NamespaceFreshnessWitnessCoordinate = Readonly<{
    canonicalCheckpoint: Uint8Array;
    canonicalVoteCarrier: Uint8Array;
    description: NamespaceFreshnessCheckpointDescription;
}>;

export type NamespaceFreshnessWitnessStoreSnapshot =
    | Readonly<{ kind: 'authorized-empty' }>
    | Readonly<{
          kind: 'current';
          coordinate: NamespaceFreshnessWitnessCoordinate;
      }>;

export type NamespaceFreshnessWitnessCompareAndLockResult =
    | Readonly<{ kind: 'committed' }>
    | Readonly<{ kind: 'changed' }>
    | Readonly<{ kind: 'authentication-failed' }>;

/**
 * The store owns one crash-consistent, authenticated compare-and-lock
 * transaction. `authorized-empty` is an explicit provisioning state; losing
 * an initialized database must return `authentication-failed`, never empty.
 */
export type NamespaceFreshnessWitnessStore = Readonly<{
    compareAndLock(input: {
        expectedCheckpointHash?: Uint8Array;
        nextCoordinate: NamespaceFreshnessWitnessCoordinate;
    }): Promise<NamespaceFreshnessWitnessCompareAndLockResult>;
    load(): Promise<
        | NamespaceFreshnessWitnessStoreSnapshot
        | Readonly<{ kind: 'authentication-failed' }>
    >;
    retire(): Promise<void>;
}>;

export type NamespaceFreshnessWitnessServiceState =
    | 'active'
    | 'retired';

export type NamespaceFreshnessWitnessService = Readonly<{
    state(): NamespaceFreshnessWitnessServiceState;
    vote(canonicalCheckpoint: Uint8Array): Promise<VerificationResult<Uint8Array>>;
}>;

export type NamespaceFreshnessLocalHead = Readonly<{
    authenticatedHeadDigest: Uint8Array;
    namespaceSequence: bigint;
    storageInstanceIdentity: Uint8Array;
}>;

/** Local authentication is necessary but explicitly not a freshness source. */
export type NamespaceFreshnessLocalAuthority = Readonly<{
    authenticateCurrentHead(): Promise<NamespaceFreshnessLocalHead>;
    retireActionSecrets(): Promise<void>;
}>;

export type NamespaceFreshnessCertificateTransport = Readonly<{
    publishCheckpoint(
        canonicalCheckpoint: Uint8Array,
    ): Promise<UntrustedNamespaceFreshnessCertificate>;
    readAvailableCertificates(): Promise<
        readonly UntrustedNamespaceFreshnessCertificate[]
    >;
}>;

/** A local copy is a cache for restart ergonomics, never freshness authority. */
export type NamespaceFreshnessAcceptedCheckpointJournal = Readonly<{
    storeAcceptedCertificate(
        certificate: VerifiedNamespaceFreshnessCertificate,
        description: NamespaceFreshnessCheckpointDescription,
    ): Promise<void>;
}>;

export type NamespaceFreshnessSubjectState =
    | 'active'
    | 'unavailable'
    | 'retired';

export type NamespaceFreshnessRetirementReason =
    | 'competingCertificates'
    | 'contextChanged'
    | 'invalidCertificate'
    | 'localAuthenticationFailed'
    | 'localStateMismatch';

export type NamespaceFreshnessSubjectRuntime = Readonly<{
    activeCapability(): NamespaceFreshnessActiveCapability;
    certifyMutation(
        durableMutation: () => Promise<void>,
    ): Promise<NamespaceFreshnessSubjectState>;
    retirementReason(): NamespaceFreshnessRetirementReason | undefined;
    startup(): Promise<NamespaceFreshnessSubjectState>;
    state(): NamespaceFreshnessSubjectState;
}>;

export type NamespaceFreshnessErrorCode =
    | 'InvalidConfiguration'
    | 'InvalidState'
    | 'RetirementFailed';

export class NamespaceFreshnessError extends Error {
    public constructor(
        public readonly code: NamespaceFreshnessErrorCode,
        message: string,
        public readonly failureCause?: unknown,
    ) {
        super(message);
        this.name = 'NamespaceFreshnessError';
    }
}

const refused = <Value>(
    refusalReason: RefusalReason,
): VerificationResult<Value> => Object.freeze({ isValid: false, refusalReason });

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

const copyExactBytes = (
    value: unknown,
    label: string,
): Uint8Array<ArrayBuffer> => {
    if (!isUint8Array(value) || value.byteLength !== hashByteLength) {
        throw new NamespaceFreshnessError(
            'InvalidConfiguration',
            `${label} must contain exactly ${String(hashByteLength)} bytes.`,
        );
    }
    return Uint8Array.from(value);
};

const bytesEqual = (left: Uint8Array, right: Uint8Array): boolean => {
    if (left.byteLength !== right.byteLength) {
        return false;
    }
    let difference = 0;
    for (let index = 0; index < left.byteLength; index += 1) {
        difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
    }
    return difference === 0;
};

const bytesKey = (bytes: Uint8Array): string =>
    Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

const copyContext = (
    context: NamespaceFreshnessContext,
): NamespaceFreshnessContext =>
    Object.freeze({
        actionContextHash: copyExactBytes(
            context.actionContextHash,
            'actionContextHash',
        ),
        ceremonyContextHash: copyExactBytes(
            context.ceremonyContextHash,
            'ceremonyContextHash',
        ),
        storageInstanceIdentity: copyExactBytes(
            context.storageInstanceIdentity,
            'storageInstanceIdentity',
        ),
        subjectParticipantIdentity: copyExactBytes(
            context.subjectParticipantIdentity,
            'subjectParticipantIdentity',
        ),
        suiteIdentifier: copyExactBytes(
            context.suiteIdentifier,
            'suiteIdentifier',
        ),
    });

const contextMatches = (
    description: NamespaceFreshnessContext,
    context: NamespaceFreshnessContext,
): boolean =>
    bytesEqual(description.suiteIdentifier, context.suiteIdentifier) &&
    bytesEqual(
        description.ceremonyContextHash,
        context.ceremonyContextHash,
    ) &&
    bytesEqual(description.actionContextHash, context.actionContextHash) &&
    bytesEqual(
        description.subjectParticipantIdentity,
        context.subjectParticipantIdentity,
    ) &&
    bytesEqual(
        description.storageInstanceIdentity,
        context.storageInstanceIdentity,
    );

const requireDescription = (
    description: NamespaceFreshnessCheckpointDescription,
    context: NamespaceFreshnessContext,
): boolean =>
    description.version === checkpointVersion &&
    description.namespaceSequence >= 0n &&
    description.namespaceSequence <= maximumUnsigned64 &&
    description.authenticatedHeadDigest.byteLength === hashByteLength &&
    description.checkpointHash.byteLength === hashByteLength &&
    (description.previousCheckpointHash === undefined
        ? description.namespaceSequence === 0n
        : description.previousCheckpointHash.byteLength === hashByteLength &&
          description.namespaceSequence > 0n) &&
    contextMatches(description, context);

const copyDescription = (
    description: NamespaceFreshnessCheckpointDescription,
): NamespaceFreshnessCheckpointDescription =>
    Object.freeze({
        actionContextHash: Uint8Array.from(description.actionContextHash),
        authenticatedHeadDigest: Uint8Array.from(
            description.authenticatedHeadDigest,
        ),
        ceremonyContextHash: Uint8Array.from(
            description.ceremonyContextHash,
        ),
        checkpointHash: Uint8Array.from(description.checkpointHash),
        namespaceSequence: description.namespaceSequence,
        ...(description.previousCheckpointHash === undefined
            ? {}
            : {
                  previousCheckpointHash: Uint8Array.from(
                      description.previousCheckpointHash,
                  ),
              }),
        storageInstanceIdentity: Uint8Array.from(
            description.storageInstanceIdentity,
        ),
        subjectParticipantIdentity: Uint8Array.from(
            description.subjectParticipantIdentity,
        ),
        suiteIdentifier: Uint8Array.from(description.suiteIdentifier),
        version: checkpointVersion,
    });

const validateWitnessUniverse = (
    context: NamespaceFreshnessContext,
    externalRosterWitnessIdentities: readonly Uint8Array[],
    freshnessQuorum: number,
): readonly Uint8Array[] => {
    if (
        !Array.isArray(externalRosterWitnessIdentities) ||
        externalRosterWitnessIdentities.length === 0 ||
        !Number.isSafeInteger(freshnessQuorum) ||
        freshnessQuorum <= 0 ||
        freshnessQuorum > externalRosterWitnessIdentities.length
    ) {
        throw new NamespaceFreshnessError(
            'InvalidConfiguration',
            'The freshness witness universe or quorum is invalid.',
        );
    }
    const identities = externalRosterWitnessIdentities.map((identity) =>
        copyExactBytes(identity, 'externalRosterWitnessIdentity'),
    );
    const identityKeys = identities.map(bytesKey);
    if (
        new Set(identityKeys).size !== identityKeys.length ||
        identities.some((identity) =>
            bytesEqual(identity, context.subjectParticipantIdentity),
        )
    ) {
        throw new NamespaceFreshnessError(
            'InvalidConfiguration',
            'Freshness witnesses must be distinct non-subject roster identities.',
        );
    }
    return Object.freeze(identities);
};

export const openNamespaceFreshnessWitnessService = (input: {
    context: NamespaceFreshnessContext;
    signer: NamespaceFreshnessClosedWitnessSigner;
    store: NamespaceFreshnessWitnessStore;
    verifier: NamespaceFreshnessVerifier;
    witnessParticipantIdentity: Uint8Array;
}): NamespaceFreshnessWitnessService => {
    const context = copyContext(input.context);
    const witnessParticipantIdentity = copyExactBytes(
        input.witnessParticipantIdentity,
        'witnessParticipantIdentity',
    );
    if (
        bytesEqual(
            witnessParticipantIdentity,
            context.subjectParticipantIdentity,
        )
    ) {
        throw new NamespaceFreshnessError(
            'InvalidConfiguration',
            'A subject cannot witness its own namespace freshness.',
        );
    }
    let state: NamespaceFreshnessWitnessServiceState = 'active';

    const retire = async (): Promise<void> => {
        if (state === 'retired') {
            return;
        }
        state = 'retired';
        await input.store.retire();
    };

    return Object.freeze({
        state: () => state,
        vote: async (
            canonicalCheckpoint,
        ): Promise<VerificationResult<Uint8Array>> => {
            if (state === 'retired') {
                return refused('consumedState');
            }
            const verifiedCheckpoint = input.verifier.verifyCheckpoint({
                canonicalCheckpoint,
                expectedContext: context,
            });
            if (!verifiedCheckpoint.isValid) {
                return refused(verifiedCheckpoint.refusalReason);
            }
            const description = verifiedCheckpoint.value.description;
            if (!requireDescription(description, context)) {
                return refused('wrongContext');
            }
            let snapshot;
            try {
                snapshot = await input.store.load();
            } catch {
                await retire();
                return refused('consumedState');
            }
            if (snapshot.kind === 'authentication-failed') {
                await retire();
                return refused('consumedState');
            }
            if (snapshot.kind === 'current') {
                const current = snapshot.coordinate;
                if (
                    bytesEqual(
                        current.description.checkpointHash,
                        description.checkpointHash,
                    )
                ) {
                    if (
                        !bytesEqual(
                            current.canonicalCheckpoint,
                            canonicalCheckpoint,
                        )
                    ) {
                        await retire();
                        return refused('equivocation');
                    }
                    return Object.freeze({
                        isValid: true,
                        value: Uint8Array.from(current.canonicalVoteCarrier),
                    });
                }
                if (
                    description.namespaceSequence !==
                        current.description.namespaceSequence + 1n ||
                    description.previousCheckpointHash === undefined ||
                    !bytesEqual(
                        description.previousCheckpointHash,
                        current.description.checkpointHash,
                    )
                ) {
                    return refused('equivocation');
                }
            } else if (
                description.namespaceSequence !== 0n ||
                description.previousCheckpointHash !== undefined
            ) {
                return refused('missingPrerequisite');
            }

            let canonicalVoteCarrier: Uint8Array;
            try {
                canonicalVoteCarrier =
                    await input.signer.signVerifiedCheckpoint({
                        verifiedCheckpoint:
                            verifiedCheckpoint.value.verifiedCheckpoint,
                        witnessParticipantIdentity,
                    });
            } catch {
                return refused('consumedState');
            }
            if (
                !isUint8Array(canonicalVoteCarrier) ||
                canonicalVoteCarrier.byteLength === 0
            ) {
                return refused('wrongTypeOrLength');
            }
            const verifiedOwnVote = input.verifier.verifyVoteCarrier({
                expectedWitnessParticipantIdentity:
                    witnessParticipantIdentity,
                untrustedVoteCarrier: canonicalVoteCarrier,
                verifiedCheckpoint:
                    verifiedCheckpoint.value.verifiedCheckpoint,
            });
            if (!verifiedOwnVote.isValid) {
                return refused(verifiedOwnVote.refusalReason);
            }
            const nextCoordinate: NamespaceFreshnessWitnessCoordinate =
                Object.freeze({
                    canonicalCheckpoint: Uint8Array.from(canonicalCheckpoint),
                    canonicalVoteCarrier:
                        Uint8Array.from(canonicalVoteCarrier),
                    description: copyDescription(description),
                });
            const expectedCheckpointHash =
                snapshot.kind === 'current'
                    ? snapshot.coordinate.description.checkpointHash
                    : undefined;
            let result: NamespaceFreshnessWitnessCompareAndLockResult;
            try {
                result = await input.store.compareAndLock({
                    ...(expectedCheckpointHash === undefined
                        ? {}
                        : { expectedCheckpointHash }),
                    nextCoordinate,
                });
            } catch {
                await retire();
                return refused('consumedState');
            }
            if (result.kind === 'authentication-failed') {
                await retire();
                return refused('consumedState');
            }
            if (result.kind === 'changed') {
                let current;
                try {
                    current = await input.store.load();
                } catch {
                    await retire();
                    return refused('consumedState');
                }
                if (current.kind === 'authentication-failed') {
                    await retire();
                    return refused('consumedState');
                }
                if (
                    current.kind === 'current' &&
                    bytesEqual(
                        current.coordinate.description.checkpointHash,
                        description.checkpointHash,
                    ) &&
                    bytesEqual(
                        current.coordinate.canonicalCheckpoint,
                        canonicalCheckpoint,
                    )
                ) {
                    return Object.freeze({
                        isValid: true,
                        value: Uint8Array.from(
                            current.coordinate.canonicalVoteCarrier,
                        ),
                    });
                }
                return refused('equivocation');
            }
            return Object.freeze({
                isValid: true,
                value: Uint8Array.from(canonicalVoteCarrier),
            });
        },
    });
};

type AcceptedCertificate = NamespaceFreshnessVerifiedCertificate &
    Readonly<{ canonicalCheckpoint: Uint8Array }>;

export const openNamespaceFreshnessSubjectRuntime = (input: {
    acceptedCheckpointJournal: NamespaceFreshnessAcceptedCheckpointJournal;
    certificateTransport: NamespaceFreshnessCertificateTransport;
    context: NamespaceFreshnessContext;
    externalRosterWitnessIdentities: readonly Uint8Array[];
    freshnessQuorum: number;
    localAuthority: NamespaceFreshnessLocalAuthority;
    verifier: NamespaceFreshnessVerifier;
}): NamespaceFreshnessSubjectRuntime => {
    const context = copyContext(input.context);
    const witnessIdentities = validateWitnessUniverse(
        context,
        input.externalRosterWitnessIdentities,
        input.freshnessQuorum,
    );
    let state: NamespaceFreshnessSubjectState = 'unavailable';
    let retirementReason: NamespaceFreshnessRetirementReason | undefined;
    let acceptedCertificate: AcceptedCertificate | undefined;
    let activeCapability: NamespaceFreshnessActiveCapability | undefined;
    let operationActive = false;

    const retire = async (
        reason: NamespaceFreshnessRetirementReason,
        failureCause?: unknown,
    ): Promise<NamespaceFreshnessSubjectState> => {
        if (state === 'retired') {
            return state;
        }
        state = 'retired';
        retirementReason = reason;
        activeCapability = undefined;
        try {
            await input.localAuthority.retireActionSecrets();
        } catch (cleanupFailure) {
            throw new NamespaceFreshnessError(
                'RetirementFailed',
                'Namespace freshness retired, but action-secret cleanup failed.',
                Object.freeze({ cleanupFailure, failureCause }),
            );
        }
        return state;
    };

    const activate = async (
        certificate: AcceptedCertificate,
    ): Promise<NamespaceFreshnessSubjectState> => {
        await input.acceptedCheckpointJournal.storeAcceptedCertificate(
            certificate.verifiedCertificate,
            certificate.description,
        );
        acceptedCertificate = certificate;
        activeCapability = Object.freeze(
            Object.create(null),
        ) as NamespaceFreshnessActiveCapability;
        state = 'active';
        return state;
    };

    const verifyUntrustedCertificate = (
        untrusted: UntrustedNamespaceFreshnessCertificate,
    ):
        | Readonly<{ kind: 'accepted'; certificate: AcceptedCertificate }>
        | Readonly<{ kind: 'unavailable' }>
        | Readonly<{ kind: 'invalid' }> => {
        if (
            typeof untrusted !== 'object' ||
            untrusted === null ||
            !isUint8Array(untrusted.canonicalCheckpoint) ||
            !Array.isArray(untrusted.untrustedVoteCarriers)
        ) {
            return { kind: 'invalid' };
        }
        const verification = input.verifier.verifyCertificate({
            canonicalCheckpoint: untrusted.canonicalCheckpoint,
            expectedContext: context,
            externalRosterWitnessIdentities: witnessIdentities,
            freshnessQuorum: input.freshnessQuorum,
            untrustedVoteCarriers: untrusted.untrustedVoteCarriers,
        });
        if (!verification.isValid) {
            return verification.refusalReason === 'missingPrerequisite'
                ? { kind: 'unavailable' }
                : { kind: 'invalid' };
        }
        const verifiedWitnessIdentities =
            verification.value.verifiedWitnessIdentities;
        if (
            !requireDescription(verification.value.description, context) ||
            !Array.isArray(verifiedWitnessIdentities) ||
            verifiedWitnessIdentities.length < input.freshnessQuorum ||
            verifiedWitnessIdentities.length > witnessIdentities.length
        ) {
            return { kind: 'invalid' };
        }
        let previousRosterPosition = -1;
        const observedWitnessKeys = new Set<string>();
        for (const witnessIdentity of verifiedWitnessIdentities) {
            if (
                !isUint8Array(witnessIdentity) ||
                witnessIdentity.byteLength !== hashByteLength
            ) {
                return { kind: 'invalid' };
            }
            const witnessKey = bytesKey(witnessIdentity);
            const rosterPosition = witnessIdentities.findIndex((identity) =>
                bytesEqual(identity, witnessIdentity),
            );
            if (
                rosterPosition <= previousRosterPosition ||
                observedWitnessKeys.has(witnessKey)
            ) {
                return { kind: 'invalid' };
            }
            previousRosterPosition = rosterPosition;
            observedWitnessKeys.add(witnessKey);
        }
        return {
            kind: 'accepted',
            certificate: Object.freeze({
                description: copyDescription(
                    verification.value.description,
                ),
                canonicalCheckpoint: Uint8Array.from(
                    untrusted.canonicalCheckpoint,
                ),
                verifiedCertificate: verification.value.verifiedCertificate,
                verifiedWitnessIdentities: Object.freeze(
                    verification.value.verifiedWitnessIdentities.map(
                        (identity) => Uint8Array.from(identity),
                    ),
                ),
            }),
        };
    };

    const selectFreshestCompleteChain = (
        candidates: readonly AcceptedCertificate[],
    ):
        | Readonly<{ kind: 'accepted'; certificate: AcceptedCertificate }>
        | Readonly<{ kind: 'competing' }>
        | Readonly<{ kind: 'unavailable' }> => {
        if (candidates.length === 0) {
            return { kind: 'unavailable' };
        }
        const bySequence = new Map<bigint, AcceptedCertificate>();
        const byHash = new Map<string, AcceptedCertificate>();
        for (const candidate of candidates) {
            const hashKey = bytesKey(candidate.description.checkpointHash);
            const existingHash = byHash.get(hashKey);
            if (
                existingHash !== undefined &&
                !bytesEqual(
                    existingHash.canonicalCheckpoint,
                    candidate.canonicalCheckpoint,
                )
            ) {
                return { kind: 'competing' };
            }
            byHash.set(hashKey, candidate);
            const existingSequence = bySequence.get(
                candidate.description.namespaceSequence,
            );
            if (
                existingSequence !== undefined &&
                !bytesEqual(
                    existingSequence.description.checkpointHash,
                    candidate.description.checkpointHash,
                )
            ) {
                return { kind: 'competing' };
            }
            bySequence.set(candidate.description.namespaceSequence, candidate);
        }
        const ordered = [...bySequence.values()].sort((left, right) =>
            left.description.namespaceSequence < right.description.namespaceSequence
                ? -1
                : left.description.namespaceSequence >
                    right.description.namespaceSequence
                  ? 1
                  : 0,
        );
        let previous = acceptedCertificate;
        let highest = acceptedCertificate;
        for (const candidate of ordered) {
            if (
                previous !== undefined &&
                candidate.description.namespaceSequence <=
                    previous.description.namespaceSequence
            ) {
                continue;
            }
            if (previous === undefined) {
                if (
                    candidate.description.namespaceSequence !== 0n ||
                    candidate.description.previousCheckpointHash !== undefined
                ) {
                    return { kind: 'unavailable' };
                }
            } else if (
                candidate.description.namespaceSequence !==
                    previous.description.namespaceSequence + 1n ||
                candidate.description.previousCheckpointHash === undefined ||
                !bytesEqual(
                    candidate.description.previousCheckpointHash,
                    previous.description.checkpointHash,
                )
            ) {
                return { kind: 'competing' };
            }
            previous = candidate;
            highest = candidate;
        }
        return highest === undefined
            ? { kind: 'unavailable' }
            : { kind: 'accepted', certificate: highest };
    };

    const authenticateLocalHead = async (): Promise<
        | Readonly<{ kind: 'authenticated'; head: NamespaceFreshnessLocalHead }>
        | Readonly<{ kind: 'failed'; failureCause: unknown }>
    > => {
        try {
            const head = await input.localAuthority.authenticateCurrentHead();
            if (
                !isUint8Array(head.authenticatedHeadDigest) ||
                head.authenticatedHeadDigest.byteLength !== hashByteLength ||
                !isUint8Array(head.storageInstanceIdentity) ||
                head.storageInstanceIdentity.byteLength !== hashByteLength ||
                typeof head.namespaceSequence !== 'bigint' ||
                head.namespaceSequence < 0n ||
                head.namespaceSequence > maximumUnsigned64
            ) {
                return { kind: 'failed', failureCause: head };
            }
            return { kind: 'authenticated', head };
        } catch (failureCause) {
            return { kind: 'failed', failureCause };
        }
    };

    const reconcile = async (
        certificate: AcceptedCertificate,
    ): Promise<NamespaceFreshnessSubjectState> => {
        const local = await authenticateLocalHead();
        if (local.kind === 'failed') {
            return retire('localAuthenticationFailed', local.failureCause);
        }
        if (
            !bytesEqual(
                local.head.storageInstanceIdentity,
                context.storageInstanceIdentity,
            )
        ) {
            return retire('contextChanged');
        }
        const description = certificate.description;
        if (
            local.head.namespaceSequence === description.namespaceSequence &&
            bytesEqual(
                local.head.authenticatedHeadDigest,
                description.authenticatedHeadDigest,
            )
        ) {
            return activate(certificate);
        }
        if (local.head.namespaceSequence > description.namespaceSequence) {
            state = 'unavailable';
            activeCapability = undefined;
            return state;
        }
        return retire('localStateMismatch');
    };

    const runExclusively = async <Result>(
        operation: () => Promise<Result>,
    ): Promise<Result> => {
        if (operationActive) {
            throw new NamespaceFreshnessError(
                'InvalidState',
                'A namespace freshness operation is already active.',
            );
        }
        operationActive = true;
        try {
            return await operation();
        } finally {
            operationActive = false;
        }
    };

    return Object.freeze({
        state: () => state,
        retirementReason: () => retirementReason,
        activeCapability: () => {
            if (state !== 'active' || activeCapability === undefined) {
                throw new NamespaceFreshnessError(
                    'InvalidState',
                    'The namespace has no externally certified freshness capability.',
                );
            }
            return activeCapability;
        },
        startup: async () =>
            runExclusively(async () => {
                if (state === 'retired') {
                    return state;
                }
                state = 'unavailable';
                activeCapability = undefined;
                let untrustedCertificates;
                try {
                    untrustedCertificates =
                        await input.certificateTransport.readAvailableCertificates();
                } catch {
                    return state;
                }
                if (!Array.isArray(untrustedCertificates)) {
                    return retire('invalidCertificate');
                }
                const candidates: AcceptedCertificate[] = [];
                for (const untrusted of untrustedCertificates) {
                    const verified = verifyUntrustedCertificate(untrusted);
                    if (verified.kind === 'invalid') {
                        return retire('invalidCertificate');
                    }
                    if (verified.kind === 'accepted') {
                        candidates.push(verified.certificate);
                    }
                }
                const selected = selectFreshestCompleteChain(candidates);
                if (selected.kind === 'competing') {
                    return retire('competingCertificates');
                }
                if (selected.kind === 'unavailable') {
                    return state;
                }
                return reconcile(selected.certificate);
            }),
        certifyMutation: async (durableMutation) =>
            runExclusively(async () => {
                if (
                    state !== 'active' ||
                    acceptedCertificate === undefined ||
                    activeCapability === undefined
                ) {
                    throw new NamespaceFreshnessError(
                        'InvalidState',
                        'Only an externally certified active namespace may mutate.',
                    );
                }
                const predecessor = acceptedCertificate;
                state = 'unavailable';
                activeCapability = undefined;
                await durableMutation();
                const local = await authenticateLocalHead();
                if (local.kind === 'failed') {
                    return retire('localAuthenticationFailed', local.failureCause);
                }
                if (
                    !bytesEqual(
                        local.head.storageInstanceIdentity,
                        context.storageInstanceIdentity,
                    )
                ) {
                    return retire('contextChanged');
                }
                if (
                    local.head.namespaceSequence !==
                        predecessor.description.namespaceSequence + 1n ||
                    bytesEqual(
                        local.head.authenticatedHeadDigest,
                        predecessor.description.authenticatedHeadDigest,
                    )
                ) {
                    return retire('localStateMismatch');
                }
                const prepared = input.verifier.prepareCheckpoint({
                    context,
                    authenticatedHeadDigest:
                        local.head.authenticatedHeadDigest,
                    namespaceSequence: local.head.namespaceSequence,
                    previousCheckpointHash:
                        predecessor.description.checkpointHash,
                });
                if (
                    !prepared.isValid ||
                    !requireDescription(prepared.value.description, context)
                ) {
                    return retire('invalidCertificate');
                }
                let untrustedCertificate: UntrustedNamespaceFreshnessCertificate;
                try {
                    untrustedCertificate =
                        await input.certificateTransport.publishCheckpoint(
                            prepared.value.canonicalCheckpoint,
                        );
                } catch {
                    return state;
                }
                const verified = verifyUntrustedCertificate(untrustedCertificate);
                if (verified.kind === 'unavailable') {
                    return state;
                }
                if (
                    verified.kind === 'invalid' ||
                    !bytesEqual(
                        verified.certificate.description.checkpointHash,
                        prepared.value.description.checkpointHash,
                    )
                ) {
                    return retire('invalidCertificate');
                }
                return activate(verified.certificate);
            }),
    });
};

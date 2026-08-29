import { foundationProfile } from '@sealed-lattice/types';

import type {
    TranscriptCoreKernelCommandRuntime,
    TranscriptCoreKernelLoaderOptions,
} from './transcript-core-bridge/kernel-runtime.js';
import { instantiateTranscriptCoreKernelCommandRuntime } from './transcript-core-bridge/kernel-runtime.js';

const requestMagic = Uint8Array.of(0x53, 0x4c, 0x50, 0x53);
const responseMagic = Uint8Array.of(0x53, 0x4c, 0x50, 0x54);
const codecVersion = 1;
const openOutcomeOperation = 1;
const prepareWitnessOperation = 2;
const completeWitnessOperation = 3;
const prepareSubjectOperation = 4;
const completeSubjectOperation = 5;
const createTerminalOperation = 6;
const validateTerminalOperation = 7;
const closeOutcomeOperation = 8;
const failureStatus = 0;
const openOutcomeStatus = 1;
const preparedWitnessStatus = 2;
const completedWitnessStatus = 3;
const preparedSubjectStatus = 4;
const completedSubjectStatus = 5;
const terminalStatus = 6;
const closedOutcomeStatus = 7;
const pendingOutcomeStatus = 8;
const successOutcome = 1;
const burnOutcome = 2;
const hashByteLength = 64;
const signingVerificationKeyByteLength = 1_952;
const signatureByteLength = 3_309;
const unsigned16Maximum = 0xffff;
const unsigned32Maximum = 0xffff_ffff;
const responseHeaderByteLength = responseMagic.byteLength + 2 + 1;
const failureResponseByteLength = responseHeaderByteLength + 2;
const productionKernelBrand: unique symbol = Symbol(
    'direct-mpc-preprocessing-source-state-kernel',
);

declare const __SEALED_LATTICE_KERNEL_NORMALIZED_SHA256_HEX__:
    | string
    | undefined;
const packagedKernelSha256Hex =
    typeof __SEALED_LATTICE_KERNEL_NORMALIZED_SHA256_HEX__ === 'undefined'
        ? undefined
        : __SEALED_LATTICE_KERNEL_NORMALIZED_SHA256_HEX__;

export type DirectMpcPreprocessingSourceStateOutcome = 'burn' | 'success';

export type DirectMpcPreprocessingSourceFoundationEvidence = Readonly<{
    actionIdentifier: string;
    canonicalActionDefinitionBytes: Uint8Array;
    canonicalBoardPolicyBytes: Uint8Array;
    canonicalManifestBytes: Uint8Array;
    canonicalRosterBytes: Uint8Array;
    ceremonyIdentifier: string;
    suiteIdentity: Uint8Array;
}>;

export type OpenDirectMpcPreprocessingSourceStateKernelInput = Readonly<{
    authenticationRecordBytes: Uint8Array;
    foundationEvidence: DirectMpcPreprocessingSourceFoundationEvidence;
    joinedCustodyRecordBytes?: Uint8Array;
    publicInconsistencyCarrierBytes?: Uint8Array;
}>;

export type PreparedDirectMpcPreprocessingSourceStateAuthorization = Readonly<{
    authorizationBodyBytes: Uint8Array;
    intentBytes: Uint8Array;
    signingVerificationKey: Uint8Array;
    stateKeyIdentity: Uint8Array;
}>;

export type CompletedDirectMpcPreprocessingSourceStateWitness = Readonly<{
    stateKeyIdentity: Uint8Array;
    witnessEnvelopeBytes: Uint8Array;
}>;

export type CompletedDirectMpcPreprocessingSourceStateSubject = Readonly<{
    endorsementCarrierBytes: Uint8Array;
    stateKeyIdentity: Uint8Array;
}>;

export type VerifiedDirectMpcPreprocessingSourceStateTerminal = Readonly<{
    outcome: DirectMpcPreprocessingSourceStateOutcome;
    stateNamespaceIdentity: Uint8Array;
    terminalBytes: Uint8Array;
    terminalIdentity: Uint8Array;
}>;

export type ProductionDirectMpcPreprocessingSourceStateKernel = Readonly<{
    readonly [productionKernelBrand]: true;
    readonly localParticipantPosition: number;
    readonly outcome: DirectMpcPreprocessingSourceStateOutcome;
    readonly publicInconsistencyCarrierBytes: Uint8Array;
    readonly sourceOutcomeBodyBytes: Uint8Array;
    readonly stateNamespaceIdentity: Uint8Array;
    close(): void;
    completeSubject(input: {
        readonly authorizationBodyBytes: Uint8Array;
        readonly signature: Uint8Array;
        readonly witnessEnvelopeBytes: readonly Uint8Array[];
    }): CompletedDirectMpcPreprocessingSourceStateSubject;
    completeWitness(input: {
        readonly authorizationBodyBytes: Uint8Array;
        readonly signature: Uint8Array;
        readonly subjectPosition: number;
    }): CompletedDirectMpcPreprocessingSourceStateWitness;
    createTerminal(input: {
        readonly endorsementCarrierBytes: readonly Uint8Array[];
    }): VerifiedDirectMpcPreprocessingSourceStateTerminal;
    prepareSubject(input: {
        readonly witnessEnvelopeBytes: readonly Uint8Array[];
    }): PreparedDirectMpcPreprocessingSourceStateAuthorization;
    prepareWitness(input: {
        readonly subjectPosition: number;
    }): PreparedDirectMpcPreprocessingSourceStateAuthorization;
    validateTerminal(input: {
        readonly terminalBytes: Uint8Array;
    }): VerifiedDirectMpcPreprocessingSourceStateTerminal;
}>;

export type DirectMpcPreprocessingSourceStateKernelOpening =
    | Readonly<{ readonly status: 'pending' }>
    | Readonly<{
          readonly kernel: ProductionDirectMpcPreprocessingSourceStateKernel;
          readonly status: 'verified';
      }>;

export type DirectMpcPreprocessingSourceStateKernelErrorCode =
    | 'ConsumedState'
    | 'ContextUnavailable'
    | 'MalformedKernelResponse'
    | 'MalformedRequest'
    | 'MissingPrerequisite'
    | 'ResourceLimit'
    | 'StateVerification'
    | 'WrongContext'
    | 'WrongFoundation'
    | 'WrongPredecessor';

export class DirectMpcPreprocessingSourceStateKernelError extends Error {
    public readonly code: DirectMpcPreprocessingSourceStateKernelErrorCode;
    public readonly failureCause: unknown;

    public constructor(
        code: DirectMpcPreprocessingSourceStateKernelErrorCode,
        message: string,
        failureCause?: unknown,
    ) {
        super(message);
        this.name = 'DirectMpcPreprocessingSourceStateKernelError';
        this.code = code;
        this.failureCause = failureCause;
    }
}

const productionKernels = new WeakSet<object>();

const responseCodeByNumber = new Map<
    number,
    Exclude<
        DirectMpcPreprocessingSourceStateKernelErrorCode,
        'MalformedKernelResponse'
    >
>([
    [1, 'MalformedRequest'],
    [2, 'ResourceLimit'],
    [3, 'WrongFoundation'],
    [4, 'WrongPredecessor'],
    [5, 'WrongContext'],
    [6, 'MissingPrerequisite'],
    [7, 'StateVerification'],
    [8, 'ContextUnavailable'],
    [9, 'ConsumedState'],
]);

const malformedResponse = (
    detail: string,
): DirectMpcPreprocessingSourceStateKernelError =>
    new DirectMpcPreprocessingSourceStateKernelError(
        'MalformedKernelResponse',
        `The direct-MPC preprocessing-source state kernel returned ${detail}.`,
    );

const isUint8Array = (value: unknown): value is Uint8Array =>
    ArrayBuffer.isView(value) &&
    Object.prototype.toString.call(value) === '[object Uint8Array]';

const snapshotDataProperty = (
    value: unknown,
    propertyName: string,
    label: string,
): unknown => {
    if (typeof value !== 'object' || value === null) {
        throw new TypeError(`${label} must be an ordinary object.`);
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, propertyName);
    if (descriptor === undefined || !('value' in descriptor)) {
        throw new TypeError(
            `${label}.${propertyName} must be an ordinary data property.`,
        );
    }
    return descriptor.value;
};

const snapshotOptionalDataProperty = (
    value: unknown,
    propertyName: string,
    label: string,
): unknown => {
    if (typeof value !== 'object' || value === null) {
        throw new TypeError(`${label} must be an ordinary object.`);
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, propertyName);
    if (descriptor === undefined) {
        return undefined;
    }
    if (!('value' in descriptor)) {
        throw new TypeError(
            `${label}.${propertyName} must be an ordinary data property.`,
        );
    }
    return descriptor.value;
};

const requireInteger = (
    value: unknown,
    maximum: number,
    label: string,
): number => {
    if (
        typeof value !== 'number' ||
        !Number.isSafeInteger(value) ||
        value < 0 ||
        value > maximum
    ) {
        throw new TypeError(`${label} must be an admitted unsigned integer.`);
    }
    return value;
};

const requireBytes = (
    value: unknown,
    label: string,
    allowEmpty = false,
): Uint8Array => {
    if (
        !isUint8Array(value) ||
        (!allowEmpty && value.byteLength === 0) ||
        value.byteLength > foundationProfile.maximumCopiedBufferByteLength
    ) {
        throw new TypeError(
            `${label} must be a byte array within the absolute copied-buffer bound.`,
        );
    }
    return value;
};

const requireExactBytes = (
    value: unknown,
    byteLength: number,
    label: string,
): Uint8Array => {
    const bytes = requireBytes(value, label);
    if (bytes.byteLength !== byteLength) {
        throw new TypeError(
            `${label} must contain exactly ${byteLength} bytes.`,
        );
    }
    return bytes;
};

const unsigned16LittleEndian = (value: unknown, label: string): Uint8Array => {
    const bytes = new Uint8Array(2);
    new DataView(bytes.buffer).setUint16(
        0,
        requireInteger(value, unsigned16Maximum, label),
        true,
    );
    return bytes;
};

const unsigned32LittleEndian = (value: unknown, label: string): Uint8Array => {
    const bytes = new Uint8Array(4);
    new DataView(bytes.buffer).setUint32(
        0,
        requireInteger(value, unsigned32Maximum, label),
        true,
    );
    return bytes;
};

const boundedParts = (value: unknown, label: string): readonly Uint8Array[] => {
    const bytes = requireBytes(value, label);
    return [
        unsigned32LittleEndian(bytes.byteLength, `${label} byte length`),
        bytes,
    ];
};

const optionalBoundedParts = (
    value: unknown,
    label: string,
): readonly Uint8Array[] =>
    value === undefined
        ? [Uint8Array.of(0)]
        : [Uint8Array.of(1), ...boundedParts(value, label)];

const concatenateRequestParts = (parts: readonly Uint8Array[]): Uint8Array => {
    let byteLength = 0;
    for (const part of parts) {
        if (
            part.byteLength >
            foundationProfile.maximumCopiedBufferByteLength - byteLength
        ) {
            throw new DirectMpcPreprocessingSourceStateKernelError(
                'ResourceLimit',
                'The preprocessing-source state request exceeds the absolute copied-buffer bound.',
            );
        }
        byteLength += part.byteLength;
    }
    const output = new Uint8Array(byteLength);
    let offset = 0;
    for (const part of parts) {
        output.set(part, offset);
        offset += part.byteLength;
    }
    return output;
};

const requestHeaderParts = (operation: number): readonly Uint8Array[] => [
    requestMagic,
    unsigned16LittleEndian(codecVersion, 'State-kernel codec version'),
    Uint8Array.of(operation),
];

const encodeIdentifier = (value: unknown, label: string): Uint8Array => {
    if (typeof value !== 'string' || value.length === 0) {
        throw new TypeError(`${label} must be a nonempty string.`);
    }
    return new TextEncoder().encode(value);
};

const snapshotOpenInput = (
    input: OpenDirectMpcPreprocessingSourceStateKernelInput,
): OpenDirectMpcPreprocessingSourceStateKernelInput => {
    const foundationEvidence = snapshotDataProperty(
        input,
        'foundationEvidence',
        'Preprocessing-source state input',
    );
    const joinedCustodyRecordBytes = snapshotOptionalDataProperty(
        input,
        'joinedCustodyRecordBytes',
        'Preprocessing-source state input',
    );
    const publicInconsistencyCarrierBytes = snapshotOptionalDataProperty(
        input,
        'publicInconsistencyCarrierBytes',
        'Preprocessing-source state input',
    );
    return Object.freeze({
        authenticationRecordBytes: requireBytes(
            snapshotDataProperty(
                input,
                'authenticationRecordBytes',
                'Preprocessing-source state input',
            ),
            'Preprocessing-source authentication record',
        ).slice(),
        foundationEvidence: Object.freeze({
            actionIdentifier: snapshotDataProperty(
                foundationEvidence,
                'actionIdentifier',
                'Preprocessing-source foundation evidence',
            ) as string,
            canonicalActionDefinitionBytes: requireBytes(
                snapshotDataProperty(
                    foundationEvidence,
                    'canonicalActionDefinitionBytes',
                    'Preprocessing-source foundation evidence',
                ),
                'Canonical action definition',
            ).slice(),
            canonicalBoardPolicyBytes: requireBytes(
                snapshotDataProperty(
                    foundationEvidence,
                    'canonicalBoardPolicyBytes',
                    'Preprocessing-source foundation evidence',
                ),
                'Canonical board policy',
            ).slice(),
            canonicalManifestBytes: requireBytes(
                snapshotDataProperty(
                    foundationEvidence,
                    'canonicalManifestBytes',
                    'Preprocessing-source foundation evidence',
                ),
                'Canonical manifest',
            ).slice(),
            canonicalRosterBytes: requireBytes(
                snapshotDataProperty(
                    foundationEvidence,
                    'canonicalRosterBytes',
                    'Preprocessing-source foundation evidence',
                ),
                'Canonical roster',
            ).slice(),
            ceremonyIdentifier: snapshotDataProperty(
                foundationEvidence,
                'ceremonyIdentifier',
                'Preprocessing-source foundation evidence',
            ) as string,
            suiteIdentity: requireExactBytes(
                snapshotDataProperty(
                    foundationEvidence,
                    'suiteIdentity',
                    'Preprocessing-source foundation evidence',
                ),
                hashByteLength,
                'Suite identity',
            ).slice(),
        }),
        ...(joinedCustodyRecordBytes === undefined
            ? {}
            : {
                  joinedCustodyRecordBytes: requireBytes(
                      joinedCustodyRecordBytes,
                      'Joined-custody record',
                  ).slice(),
              }),
        ...(publicInconsistencyCarrierBytes === undefined
            ? {}
            : {
                  publicInconsistencyCarrierBytes: requireBytes(
                      publicInconsistencyCarrierBytes,
                      'Public inconsistency carrier',
                  ).slice(),
              }),
    });
};

const destroyOpenInput = (
    input: OpenDirectMpcPreprocessingSourceStateKernelInput,
): void => {
    input.authenticationRecordBytes.fill(0);
    input.foundationEvidence.canonicalActionDefinitionBytes.fill(0);
    input.foundationEvidence.canonicalBoardPolicyBytes.fill(0);
    input.foundationEvidence.canonicalManifestBytes.fill(0);
    input.foundationEvidence.canonicalRosterBytes.fill(0);
    input.foundationEvidence.suiteIdentity.fill(0);
    input.joinedCustodyRecordBytes?.fill(0);
    input.publicInconsistencyCarrierBytes?.fill(0);
};

const encodeOpenRequest = (
    input: OpenDirectMpcPreprocessingSourceStateKernelInput,
): Uint8Array => {
    const foundation = input.foundationEvidence;
    return concatenateRequestParts([
        ...requestHeaderParts(openOutcomeOperation),
        requireExactBytes(
            foundation.suiteIdentity,
            hashByteLength,
            'Suite identity',
        ),
        ...boundedParts(
            foundation.canonicalManifestBytes,
            'Canonical manifest',
        ),
        ...boundedParts(foundation.canonicalRosterBytes, 'Canonical roster'),
        ...boundedParts(
            encodeIdentifier(
                foundation.ceremonyIdentifier,
                'Ceremony identifier',
            ),
            'Ceremony identifier',
        ),
        ...boundedParts(
            encodeIdentifier(foundation.actionIdentifier, 'Action identifier'),
            'Action identifier',
        ),
        ...boundedParts(
            foundation.canonicalActionDefinitionBytes,
            'Canonical action definition',
        ),
        ...boundedParts(
            foundation.canonicalBoardPolicyBytes,
            'Canonical board policy',
        ),
        ...boundedParts(
            input.authenticationRecordBytes,
            'Authentication record',
        ),
        ...optionalBoundedParts(
            input.joinedCustodyRecordBytes,
            'Joined-custody record',
        ),
        ...optionalBoundedParts(
            input.publicInconsistencyCarrierBytes,
            'Public inconsistency carrier',
        ),
    ]);
};

const handleParts = (
    operation: number,
    contextHandle: number,
): readonly Uint8Array[] => [
    ...requestHeaderParts(operation),
    unsigned32LittleEndian(contextHandle, 'State context handle'),
];

const snapshotByteArray = (
    value: unknown,
    expectedItemCount: number,
    label: string,
): readonly Uint8Array[] => {
    if (!Array.isArray(value) || value.length !== expectedItemCount) {
        throw new TypeError(
            `${label} must contain exactly ${expectedItemCount} byte arrays.`,
        );
    }
    return Object.freeze(
        value.map((item, index) =>
            requireBytes(item, `${label} ${index}`).slice(),
        ),
    );
};

const encodeWitnessEnvelopeParts = (
    witnessEnvelopeBytes: readonly Uint8Array[],
): readonly Uint8Array[] => [
    unsigned16LittleEndian(
        witnessEnvelopeBytes.length,
        'Witness-envelope count',
    ),
    ...witnessEnvelopeBytes.flatMap((bytes, index) =>
        boundedParts(bytes, `Witness envelope ${index}`),
    ),
];

class ResponseCursor {
    readonly #bytes: Uint8Array;
    #offset = responseHeaderByteLength;

    public constructor(bytes: Uint8Array, expectedStatus: number) {
        if (bytes.byteLength < responseHeaderByteLength) {
            throw malformedResponse('a truncated response header');
        }
        for (let index = 0; index < responseMagic.byteLength; index += 1) {
            if (bytes[index] !== responseMagic[index]) {
                throw malformedResponse('the wrong response magic');
            }
        }
        const view = new DataView(
            bytes.buffer,
            bytes.byteOffset,
            bytes.byteLength,
        );
        if (view.getUint16(responseMagic.byteLength, true) !== codecVersion) {
            throw malformedResponse('an unsupported response version');
        }
        const status = bytes[responseHeaderByteLength - 1];
        if (status === failureStatus) {
            if (bytes.byteLength !== failureResponseByteLength) {
                throw malformedResponse('a malformed failure response');
            }
            const code = responseCodeByNumber.get(
                view.getUint16(responseHeaderByteLength, true),
            );
            if (code === undefined) {
                throw malformedResponse('an unknown failure code');
            }
            throw new DirectMpcPreprocessingSourceStateKernelError(
                code,
                `The direct-MPC preprocessing-source state kernel refused the request with ${code}.`,
            );
        }
        if (status !== expectedStatus) {
            throw malformedResponse('an unexpected response status');
        }
        this.#bytes = bytes;
    }

    public readUnsigned8(label: string): number {
        return this.readExact(1, label)[0] ?? 0;
    }

    public readUnsigned16(label: string): number {
        const bytes = this.readExact(2, label);
        return new DataView(
            bytes.buffer,
            bytes.byteOffset,
            bytes.byteLength,
        ).getUint16(0, true);
    }

    public readUnsigned32(label: string): number {
        const bytes = this.readExact(4, label);
        return new DataView(
            bytes.buffer,
            bytes.byteOffset,
            bytes.byteLength,
        ).getUint32(0, true);
    }

    public readExact(byteLength: number, label: string): Uint8Array {
        if (
            !Number.isSafeInteger(byteLength) ||
            byteLength < 0 ||
            byteLength > this.#bytes.byteLength - this.#offset
        ) {
            throw malformedResponse(`a truncated ${label}`);
        }
        const value = this.#bytes.slice(
            this.#offset,
            this.#offset + byteLength,
        );
        this.#offset += byteLength;
        return value;
    }

    public readBounded(label: string, allowEmpty = false): Uint8Array {
        const byteLength = this.readUnsigned32(`${label} byte length`);
        if (
            (!allowEmpty && byteLength === 0) ||
            byteLength > foundationProfile.maximumCopiedBufferByteLength
        ) {
            throw malformedResponse(`an invalid ${label} byte length`);
        }
        return this.readExact(byteLength, label);
    }

    public requireComplete(): void {
        if (this.#offset !== this.#bytes.byteLength) {
            throw malformedResponse('trailing response bytes');
        }
    }
}

const parseOutcome = (
    value: number,
): DirectMpcPreprocessingSourceStateOutcome => {
    if (value === successOutcome) {
        return 'success';
    }
    if (value === burnOutcome) {
        return 'burn';
    }
    throw malformedResponse('an invalid outcome value');
};

const parsePreparedResponse = (
    responseBytes: Uint8Array,
    expectedStatus: number,
): PreparedDirectMpcPreprocessingSourceStateAuthorization => {
    const cursor = new ResponseCursor(responseBytes, expectedStatus);
    const value = Object.freeze({
        stateKeyIdentity: cursor.readExact(
            hashByteLength,
            'state-key identity',
        ),
        intentBytes: cursor.readBounded('state intent'),
        authorizationBodyBytes: cursor.readBounded('authorization body'),
        signingVerificationKey: cursor.readExact(
            signingVerificationKeyByteLength,
            'signing verification key',
        ),
    });
    cursor.requireComplete();
    return value;
};

const parseCompletedResponse = (
    responseBytes: Uint8Array,
    expectedStatus: number,
    label: string,
): Readonly<{
    readonly payloadBytes: Uint8Array;
    readonly stateKeyIdentity: Uint8Array;
}> => {
    const cursor = new ResponseCursor(responseBytes, expectedStatus);
    const value = Object.freeze({
        stateKeyIdentity: cursor.readExact(
            hashByteLength,
            'state-key identity',
        ),
        payloadBytes: cursor.readBounded(label),
    });
    cursor.requireComplete();
    return value;
};

const parseTerminalResponse = (
    responseBytes: Uint8Array,
): VerifiedDirectMpcPreprocessingSourceStateTerminal => {
    const cursor = new ResponseCursor(responseBytes, terminalStatus);
    const value = Object.freeze({
        outcome: parseOutcome(cursor.readUnsigned8('outcome')),
        stateNamespaceIdentity: cursor.readExact(
            hashByteLength,
            'state-namespace identity',
        ),
        terminalIdentity: cursor.readExact(hashByteLength, 'terminal identity'),
        terminalBytes: cursor.readBounded('terminal'),
    });
    cursor.requireComplete();
    return value;
};

class OpenedProductionStateKernel implements ProductionDirectMpcPreprocessingSourceStateKernel {
    public readonly [productionKernelBrand] = true as const;
    public readonly localParticipantPosition: number;
    public readonly outcome: DirectMpcPreprocessingSourceStateOutcome;
    public readonly publicInconsistencyCarrierBytes: Uint8Array;
    public readonly sourceOutcomeBodyBytes: Uint8Array;
    public readonly stateNamespaceIdentity: Uint8Array;
    readonly #contextHandle: number;
    readonly #runtime: TranscriptCoreKernelCommandRuntime;
    #closed = false;

    public constructor(
        runtime: TranscriptCoreKernelCommandRuntime,
        responseBytes: Uint8Array,
    ) {
        const cursor = new ResponseCursor(responseBytes, openOutcomeStatus);
        const contextHandle = cursor.readUnsigned32('context handle');
        if (contextHandle === 0) {
            throw malformedResponse('a zero context handle');
        }
        this.#contextHandle = contextHandle;
        this.outcome = parseOutcome(cursor.readUnsigned8('outcome'));
        this.localParticipantPosition = cursor.readUnsigned16(
            'local participant position',
        );
        this.stateNamespaceIdentity = cursor.readExact(
            hashByteLength,
            'state-namespace identity',
        );
        this.sourceOutcomeBodyBytes = cursor.readBounded('source-outcome body');
        this.publicInconsistencyCarrierBytes = cursor.readBounded(
            'public inconsistency carrier',
            true,
        );
        cursor.requireComplete();
        if (
            (this.outcome === 'success' &&
                this.publicInconsistencyCarrierBytes.byteLength !== 0) ||
            (this.outcome === 'burn' &&
                this.publicInconsistencyCarrierBytes.byteLength === 0)
        ) {
            throw malformedResponse('an outcome-inconsistent public carrier');
        }
        this.#runtime = runtime;
        productionKernels.add(this);
    }

    public prepareWitness(input: {
        readonly subjectPosition: number;
    }): PreparedDirectMpcPreprocessingSourceStateAuthorization {
        this.#requireOpen();
        const request = concatenateRequestParts([
            ...handleParts(prepareWitnessOperation, this.#contextHandle),
            unsigned16LittleEndian(
                snapshotDataProperty(input, 'subjectPosition', 'Witness input'),
                'Witness subject position',
            ),
        ]);
        try {
            return parsePreparedResponse(
                this.#runtime.executeDirectMpcPreprocessingSourceState(request),
                preparedWitnessStatus,
            );
        } finally {
            request.fill(0);
        }
    }

    public completeWitness(input: {
        readonly authorizationBodyBytes: Uint8Array;
        readonly signature: Uint8Array;
        readonly subjectPosition: number;
    }): CompletedDirectMpcPreprocessingSourceStateWitness {
        this.#requireOpen();
        const request = concatenateRequestParts([
            ...handleParts(completeWitnessOperation, this.#contextHandle),
            unsigned16LittleEndian(
                snapshotDataProperty(input, 'subjectPosition', 'Witness input'),
                'Witness subject position',
            ),
            ...boundedParts(
                snapshotDataProperty(
                    input,
                    'authorizationBodyBytes',
                    'Witness input',
                ),
                'Witness authorization body',
            ),
            requireExactBytes(
                snapshotDataProperty(input, 'signature', 'Witness input'),
                signatureByteLength,
                'Witness signature',
            ),
        ]);
        try {
            const completed = parseCompletedResponse(
                this.#runtime.executeDirectMpcPreprocessingSourceState(request),
                completedWitnessStatus,
                'witness envelope',
            );
            return Object.freeze({
                stateKeyIdentity: completed.stateKeyIdentity,
                witnessEnvelopeBytes: completed.payloadBytes,
            });
        } finally {
            request.fill(0);
        }
    }

    public prepareSubject(input: {
        readonly witnessEnvelopeBytes: readonly Uint8Array[];
    }): PreparedDirectMpcPreprocessingSourceStateAuthorization {
        this.#requireOpen();
        const witnesses = snapshotByteArray(
            snapshotDataProperty(
                input,
                'witnessEnvelopeBytes',
                'Subject input',
            ),
            foundationProfile.stateWitnessQuorum,
            'Subject witness envelopes',
        );
        const request = concatenateRequestParts([
            ...handleParts(prepareSubjectOperation, this.#contextHandle),
            ...encodeWitnessEnvelopeParts(witnesses),
        ]);
        try {
            return parsePreparedResponse(
                this.#runtime.executeDirectMpcPreprocessingSourceState(request),
                preparedSubjectStatus,
            );
        } finally {
            request.fill(0);
            for (const witness of witnesses) {
                witness.fill(0);
            }
        }
    }

    public completeSubject(input: {
        readonly authorizationBodyBytes: Uint8Array;
        readonly signature: Uint8Array;
        readonly witnessEnvelopeBytes: readonly Uint8Array[];
    }): CompletedDirectMpcPreprocessingSourceStateSubject {
        this.#requireOpen();
        const witnesses = snapshotByteArray(
            snapshotDataProperty(
                input,
                'witnessEnvelopeBytes',
                'Subject input',
            ),
            foundationProfile.stateWitnessQuorum,
            'Subject witness envelopes',
        );
        const request = concatenateRequestParts([
            ...handleParts(completeSubjectOperation, this.#contextHandle),
            ...encodeWitnessEnvelopeParts(witnesses),
            ...boundedParts(
                snapshotDataProperty(
                    input,
                    'authorizationBodyBytes',
                    'Subject input',
                ),
                'Subject authorization body',
            ),
            requireExactBytes(
                snapshotDataProperty(input, 'signature', 'Subject input'),
                signatureByteLength,
                'Subject signature',
            ),
        ]);
        try {
            const completed = parseCompletedResponse(
                this.#runtime.executeDirectMpcPreprocessingSourceState(request),
                completedSubjectStatus,
                'endorsement carrier',
            );
            return Object.freeze({
                stateKeyIdentity: completed.stateKeyIdentity,
                endorsementCarrierBytes: completed.payloadBytes,
            });
        } finally {
            request.fill(0);
            for (const witness of witnesses) {
                witness.fill(0);
            }
        }
    }

    public createTerminal(input: {
        readonly endorsementCarrierBytes: readonly Uint8Array[];
    }): VerifiedDirectMpcPreprocessingSourceStateTerminal {
        this.#requireOpen();
        const carriers = snapshotByteArray(
            snapshotDataProperty(
                input,
                'endorsementCarrierBytes',
                'Terminal input',
            ),
            foundationProfile.finalityQuorum,
            'Terminal endorsement carriers',
        );
        const request = concatenateRequestParts([
            ...handleParts(createTerminalOperation, this.#contextHandle),
            unsigned16LittleEndian(
                carriers.length,
                'Terminal endorsement-carrier count',
            ),
            ...carriers.flatMap((carrier, index) =>
                boundedParts(carrier, `Terminal endorsement carrier ${index}`),
            ),
        ]);
        try {
            return parseTerminalResponse(
                this.#runtime.executeDirectMpcPreprocessingSourceState(request),
            );
        } finally {
            request.fill(0);
            for (const carrier of carriers) {
                carrier.fill(0);
            }
        }
    }

    public validateTerminal(input: {
        readonly terminalBytes: Uint8Array;
    }): VerifiedDirectMpcPreprocessingSourceStateTerminal {
        this.#requireOpen();
        const request = concatenateRequestParts([
            ...handleParts(validateTerminalOperation, this.#contextHandle),
            ...boundedParts(
                snapshotDataProperty(input, 'terminalBytes', 'Terminal input'),
                'Source terminal',
            ),
        ]);
        try {
            return parseTerminalResponse(
                this.#runtime.executeDirectMpcPreprocessingSourceState(request),
            );
        } finally {
            request.fill(0);
        }
    }

    public close(): void {
        this.#requireOpen();
        const request = concatenateRequestParts([
            ...handleParts(closeOutcomeOperation, this.#contextHandle),
        ]);
        try {
            const response =
                this.#runtime.executeDirectMpcPreprocessingSourceState(request);
            new ResponseCursor(response, closedOutcomeStatus).requireComplete();
            this.#closed = true;
        } finally {
            request.fill(0);
        }
    }

    #requireOpen(): void {
        if (this.#closed) {
            throw new DirectMpcPreprocessingSourceStateKernelError(
                'ContextUnavailable',
                'The preprocessing-source state kernel context is closed.',
            );
        }
    }
}

export const isProductionDirectMpcPreprocessingSourceStateKernel = (
    value: unknown,
): value is ProductionDirectMpcPreprocessingSourceStateKernel =>
    typeof value === 'object' && value !== null && productionKernels.has(value);

export const openProductionDirectMpcPreprocessingSourceStateKernel = async (
    input: OpenDirectMpcPreprocessingSourceStateKernelInput,
    options: TranscriptCoreKernelLoaderOptions = {},
): Promise<DirectMpcPreprocessingSourceStateKernelOpening> => {
    const snapshottedInput = snapshotOpenInput(input);
    let request: Uint8Array | undefined;
    try {
        request = encodeOpenRequest(snapshottedInput);
        const runtime = await instantiateTranscriptCoreKernelCommandRuntime(
            new URL('./sealed_lattice_kernel.wasm', import.meta.url),
            {
                ...options,
                expectedKernelSha256Hex:
                    options.expectedKernelSha256Hex ?? packagedKernelSha256Hex,
            },
        );
        const response =
            runtime.executeDirectMpcPreprocessingSourceState(request);
        if (response[responseHeaderByteLength - 1] === pendingOutcomeStatus) {
            new ResponseCursor(
                response,
                pendingOutcomeStatus,
            ).requireComplete();
            return Object.freeze({ status: 'pending' as const });
        }
        return Object.freeze({
            kernel: new OpenedProductionStateKernel(runtime, response),
            status: 'verified' as const,
        });
    } catch (error) {
        if (error instanceof DirectMpcPreprocessingSourceStateKernelError) {
            throw error;
        }
        throw new DirectMpcPreprocessingSourceStateKernelError(
            'MalformedRequest',
            'The direct-MPC preprocessing-source state boundary failed.',
            error,
        );
    } finally {
        request?.fill(0);
        destroyOpenInput(snapshottedInput);
    }
};

/* eslint-disable @typescript-eslint/no-unsafe-argument, @typescript-eslint/no-unsafe-return -- The static browser page validates its structured-clone input and then exercises dynamically served modules from the exact candidate archive. */

const candidateModuleRoot = '/candidate/dist';
const {
    actionSignatureKeyGenerationRandomnessByteLength,
    openActionSignatureRuntime,
} = await import(`${candidateModuleRoot}/action-signature-runtime.js`);
const { instantiateConstructionKernelCommandRuntime } = await import(
    `${candidateModuleRoot}/foundation-kernel/kernel-runtime.js`
);
const {
    openPairEncryptionRuntime,
    pairEncryptionKeyGenerationRandomnessByteLength,
} = await import(`${candidateModuleRoot}/pair-encryption-runtime.js`);
const { PrivatePreparationWorkerClient } = await import(
    `${candidateModuleRoot}/private-preparation-worker-client.js`
);
const { openRosterRuntime } = await import(
    `${candidateModuleRoot}/roster-runtime.js`
);

const participantCount = 10;
const preparationAttempt = 7;
const credentialDatabaseName = 'sealed-lattice-external-ceremony-credentials';
const credentialKeyStoreName = 'keys';
const credentialRecordStoreName = 'records';
const pressureStoreName = 'pressure';
const credentialRecordIdentifier = 'participant-credential';
const credentialKeyIdentifier = 'participant-credential-key';
const credentialAssociatedDataDomain =
    'sealed-lattice/external-chrome-ceremony/credential/v1';
const pressureChunkByteLength = 1_048_576;

const statusElement = document.querySelector('#status');

const setStatus = (value) => {
    if (statusElement !== null) statusElement.textContent = value;
};

const bytesToHex = (bytes) =>
    Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

const hexToBytes = (hex, expectedByteLength, name) => {
    if (
        typeof hex !== 'string' ||
        hex.length !== expectedByteLength * 2 ||
        !/^[0-9a-f]+$/u.test(hex)
    ) {
        throw new TypeError(`${name} is not canonical lowercase hexadecimal.`);
    }
    return Uint8Array.from({ length: expectedByteLength }, (_, index) =>
        Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16),
    );
};

const requireInteger = (value, minimum, maximum, name) => {
    if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
        throw new RangeError(`${name} is invalid.`);
    }
    return value;
};

const requireConfiguration = (input) => {
    if (typeof input !== 'object' || input === null || Array.isArray(input)) {
        throw new TypeError('The visit configuration is malformed.');
    }
    const configuration = input;
    if (
        typeof configuration.action !== 'string' ||
        typeof configuration.runIdentifier !== 'string' ||
        typeof configuration.visitToken !== 'string' ||
        typeof configuration.databaseName !== 'string' ||
        typeof configuration.relayPrefix !== 'string' ||
        typeof configuration.kernelSha256Hex !== 'string' ||
        typeof configuration.candidateBuildIdentityHex !== 'string' ||
        typeof configuration.runtimeIdentityHex !== 'string' ||
        typeof configuration.actionProposalIdentityHex !== 'string' ||
        typeof configuration.actionDefinitionIdentityHex !== 'string' ||
        typeof configuration.predecessorIdentityHex !== 'string'
    ) {
        throw new TypeError('The visit configuration omits a string field.');
    }
    requireInteger(
        configuration.participantPosition,
        0,
        participantCount - 1,
        'participantPosition',
    );
    requireInteger(configuration.topCount, 1, participantCount, 'topCount');
    if (
        !Array.isArray(configuration.sourceDeclarations) ||
        configuration.sourceDeclarations.length !== participantCount ||
        configuration.sourceDeclarations.some(
            (value) => value !== 'submit' && value !== 'abstain',
        )
    ) {
        throw new TypeError('sourceDeclarations is invalid.');
    }
    return configuration;
};

const requestHeaders = (configuration) => ({
    'X-Sealed-Lattice-Visit': configuration.visitToken,
});

const relayUrl = (configuration, objectName) =>
    `${configuration.relayPrefix}/${objectName}`;

const getBytes = async (configuration, objectName) => {
    const response = await fetch(relayUrl(configuration, objectName), {
        cache: 'no-store',
        headers: requestHeaders(configuration),
    });
    if (!response.ok) {
        throw new Error(
            `Relay read ${objectName} failed with HTTP ${String(response.status)}.`,
        );
    }
    return new Uint8Array(await response.arrayBuffer());
};

const putBytes = async (configuration, objectName, bytes) => {
    const response = await fetch(relayUrl(configuration, objectName), {
        body: bytes,
        cache: 'no-store',
        headers: {
            ...requestHeaders(configuration),
            'Content-Type': 'application/octet-stream',
        },
        method: 'PUT',
    });
    if (!response.ok) {
        throw new Error(
            `Relay write ${objectName} failed with HTTP ${String(response.status)}.`,
        );
    }
};

const transactionCompletion = (transaction) =>
    new Promise((resolve, reject) => {
        transaction.addEventListener('complete', () => resolve(), {
            once: true,
        });
        transaction.addEventListener(
            'abort',
            () => reject(new Error('An IndexedDB transaction aborted.')),
            { once: true },
        );
        transaction.addEventListener(
            'error',
            () => reject(new Error('An IndexedDB transaction failed.')),
            { once: true },
        );
    });

const requestResult = (request) =>
    new Promise((resolve, reject) => {
        request.addEventListener('success', () => resolve(request.result), {
            once: true,
        });
        request.addEventListener(
            'error',
            () => reject(new Error('An IndexedDB request failed.')),
            { once: true },
        );
    });

const openDatabase = (name, version, onUpgrade) =>
    new Promise((resolve, reject) => {
        const request =
            version === undefined
                ? indexedDB.open(name)
                : indexedDB.open(name, version);
        request.addEventListener(
            'upgradeneeded',
            () => onUpgrade?.(request.result),
            { once: true },
        );
        request.addEventListener('success', () => resolve(request.result), {
            once: true,
        });
        request.addEventListener(
            'error',
            () => reject(new Error(`Database ${name} failed to open.`)),
            { once: true },
        );
    });

const openCredentialDatabase = () =>
    openDatabase(credentialDatabaseName, 1, (database) => {
        for (const storeName of [
            credentialKeyStoreName,
            credentialRecordStoreName,
            pressureStoreName,
        ]) {
            if (!database.objectStoreNames.contains(storeName)) {
                database.createObjectStore(storeName);
            }
        }
    });

const deleteDatabase = (name) =>
    new Promise((resolve, reject) => {
        const request = indexedDB.deleteDatabase(name);
        request.addEventListener('success', () => resolve(), { once: true });
        request.addEventListener(
            'blocked',
            () => reject(new Error(`Database ${name} remained open.`)),
            { once: true },
        );
        request.addEventListener(
            'error',
            () => reject(new Error(`Database ${name} could not be deleted.`)),
            { once: true },
        );
    });

const credentialAssociatedData = (configuration) =>
    new TextEncoder().encode(
        [
            credentialAssociatedDataDomain,
            configuration.runIdentifier,
            configuration.participantPosition,
            configuration.candidateBuildIdentityHex,
        ].join('\n'),
    );

const encodeCredential = (signingSecretKey, mailboxDecapsulationKey) => {
    const output = new Uint8Array(
        8 + signingSecretKey.byteLength + mailboxDecapsulationKey.byteLength,
    );
    const view = new DataView(output.buffer);
    view.setUint32(0, signingSecretKey.byteLength, true);
    view.setUint32(4, mailboxDecapsulationKey.byteLength, true);
    output.set(signingSecretKey, 8);
    output.set(mailboxDecapsulationKey, 8 + signingSecretKey.byteLength);
    return output;
};

const decodeCredential = (bytes) => {
    if (bytes.byteLength < 8) {
        throw new Error('The retained credential is truncated.');
    }
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const signingLength = view.getUint32(0, true);
    const mailboxLength = view.getUint32(4, true);
    if (8 + signingLength + mailboxLength !== bytes.byteLength) {
        throw new Error('The retained credential lengths are invalid.');
    }
    return {
        mailboxDecapsulationKey: bytes.slice(8 + signingLength),
        signingSecretKey: bytes.slice(8, 8 + signingLength),
    };
};

const storeCredential = async (
    configuration,
    signingSecretKey,
    mailboxDecapsulationKey,
) => {
    await navigator.locks.request(
        `sealed-lattice-external-ceremony-credential:${configuration.runIdentifier}`,
        { mode: 'exclusive' },
        async () => {
            const database = await openCredentialDatabase();
            try {
                const existingTransaction = database.transaction(
                    [credentialKeyStoreName, credentialRecordStoreName],
                    'readonly',
                );
                const [existingKey, existingRecord] = await Promise.all([
                    requestResult(
                        existingTransaction
                            .objectStore(credentialKeyStoreName)
                            .get(credentialKeyIdentifier),
                    ),
                    requestResult(
                        existingTransaction
                            .objectStore(credentialRecordStoreName)
                            .get(credentialRecordIdentifier),
                    ),
                ]);
                await transactionCompletion(existingTransaction);
                if (existingKey !== undefined || existingRecord !== undefined) {
                    throw new Error('The join credential already exists.');
                }
                const key = await crypto.subtle.generateKey(
                    { length: 256, name: 'AES-GCM' },
                    false,
                    ['encrypt', 'decrypt'],
                );
                const nonce = crypto.getRandomValues(new Uint8Array(12));
                const plaintext = encodeCredential(
                    signingSecretKey,
                    mailboxDecapsulationKey,
                );
                const ciphertext = new Uint8Array(
                    await crypto.subtle.encrypt(
                        {
                            additionalData:
                                credentialAssociatedData(configuration),
                            iv: nonce,
                            name: 'AES-GCM',
                            tagLength: 128,
                        },
                        key,
                        plaintext,
                    ),
                );
                plaintext.fill(0);
                const transaction = database.transaction(
                    [credentialKeyStoreName, credentialRecordStoreName],
                    'readwrite',
                    { durability: 'strict' },
                );
                transaction
                    .objectStore(credentialKeyStoreName)
                    .put(key, credentialKeyIdentifier);
                transaction
                    .objectStore(credentialRecordStoreName)
                    .put({ ciphertext, nonce }, credentialRecordIdentifier);
                await transactionCompletion(transaction);
            } finally {
                database.close();
            }
        },
    );
};

const readCredential = async (configuration) => {
    const database = await openCredentialDatabase();
    try {
        const transaction = database.transaction(
            [credentialKeyStoreName, credentialRecordStoreName],
            'readonly',
        );
        const [key, record] = await Promise.all([
            requestResult(
                transaction
                    .objectStore(credentialKeyStoreName)
                    .get(credentialKeyIdentifier),
            ),
            requestResult(
                transaction
                    .objectStore(credentialRecordStoreName)
                    .get(credentialRecordIdentifier),
            ),
        ]);
        await transactionCompletion(transaction);
        if (!(key instanceof CryptoKey)) {
            throw new Error('The nonexportable credential key is absent.');
        }
        if (
            typeof record !== 'object' ||
            record === null ||
            !(record.ciphertext instanceof Uint8Array) ||
            !(record.nonce instanceof Uint8Array)
        ) {
            throw new Error('The encrypted credential record is absent.');
        }
        const plaintext = new Uint8Array(
            await crypto.subtle.decrypt(
                {
                    additionalData: credentialAssociatedData(configuration),
                    iv: record.nonce,
                    name: 'AES-GCM',
                    tagLength: 128,
                },
                key,
                record.ciphertext,
            ),
        );
        try {
            return decodeCredential(plaintext);
        } finally {
            plaintext.fill(0);
        }
    } finally {
        database.close();
    }
};

const deleteCredential = async () => {
    const database = await openCredentialDatabase();
    try {
        const transaction = database.transaction(
            [credentialKeyStoreName, credentialRecordStoreName],
            'readwrite',
            { durability: 'strict' },
        );
        transaction
            .objectStore(credentialKeyStoreName)
            .delete(credentialKeyIdentifier);
        transaction
            .objectStore(credentialRecordStoreName)
            .delete(credentialRecordIdentifier);
        await transactionCompletion(transaction);
    } finally {
        database.close();
    }
};

const storageEstimate = async () => {
    const estimate = await navigator.storage.estimate();
    if (
        !Number.isSafeInteger(estimate.quota) ||
        !Number.isSafeInteger(estimate.usage)
    ) {
        throw new Error('Chrome returned an incomplete storage estimate.');
    }
    return {
        quota: estimate.quota,
        usage: estimate.usage,
        usageDetails: Object.fromEntries(
            Object.entries(estimate.usageDetails ?? {}).filter(
                ([, value]) => typeof value === 'number',
            ),
        ),
    };
};

const requirePlatform = async () => {
    const availability = {
        crypto: globalThis.crypto !== undefined,
        indexedDb: globalThis.indexedDB !== undefined,
        locks: navigator.locks !== undefined,
        persistentStorage:
            navigator.storage !== undefined &&
            typeof navigator.storage.persist === 'function' &&
            typeof navigator.storage.persisted === 'function',
        secureContext: globalThis.isSecureContext,
        subtleCrypto: globalThis.crypto?.subtle !== undefined,
        webAssembly: globalThis.WebAssembly !== undefined,
        worker: globalThis.Worker !== undefined,
    };
    if (Object.values(availability).some((value) => !value)) {
        throw new Error('The browser feature preflight failed.');
    }
    const persistedBefore = await navigator.storage.persisted();
    const persistRequest = persistedBefore
        ? true
        : await navigator.storage.persist();
    const persistedAfter = await navigator.storage.persisted();
    return { availability, persistRequest, persistedAfter, persistedBefore };
};

const actionContext = (configuration) => ({
    actionDefinitionIdentity: hexToBytes(
        configuration.actionDefinitionIdentityHex,
        64,
        'actionDefinitionIdentityHex',
    ),
    actionProposalIdentity: hexToBytes(
        configuration.actionProposalIdentityHex,
        64,
        'actionProposalIdentityHex',
    ),
    participantPosition: configuration.participantPosition,
    predecessorIdentity: hexToBytes(
        configuration.predecessorIdentityHex,
        64,
        'predecessorIdentityHex',
    ),
});

const workerInitialization = (configuration) => ({
    candidateBuildIdentity: hexToBytes(
        configuration.candidateBuildIdentityHex,
        64,
        'candidateBuildIdentityHex',
    ),
    databaseName: configuration.databaseName,
    kernelOptions: {
        expectedKernelSha256Hex: configuration.kernelSha256Hex,
    },
    kernelUrl: new URL(
        '/candidate/dist/sealed-lattice-kernel.wasm',
        globalThis.location.origin,
    ).href,
    runtimeIdentity: hexToBytes(
        configuration.runtimeIdentityHex,
        64,
        'runtimeIdentityHex',
    ),
});

const workerInitializationLimitMilliseconds = 60_000;

const openWorkerClient = async (configuration) => {
    setStatus('opening the participant worker');
    let timeoutIdentifier;
    try {
        return await Promise.race([
            PrivatePreparationWorkerClient.create(
                new URL(
                    '/external-chrome-ceremony-worker.mjs',
                    globalThis.location.origin,
                ),
                workerInitialization(configuration),
            ),
            new Promise((_, reject) => {
                timeoutIdentifier = setTimeout(
                    () =>
                        reject(
                            new Error(
                                'The participant worker did not initialize within one minute.',
                            ),
                        ),
                    workerInitializationLimitMilliseconds,
                );
            }),
        ]);
    } finally {
        clearTimeout(timeoutIdentifier);
    }
};

const workerTransferables = (request) => {
    const transferables = [];
    const visit = (value) => {
        if (
            value instanceof Uint8Array &&
            value.buffer instanceof ArrayBuffer
        ) {
            transferables.push(value.buffer);
            return;
        }
        if (Array.isArray(value)) {
            for (const entry of value) visit(entry);
            return;
        }
        if (typeof value === 'object' && value !== null) {
            for (const entry of Object.values(value)) visit(entry);
        }
    };
    visit(request.input);
    return transferables;
};

const runUntilCrashBoundary = async (
    configuration,
    boundary,
    requestOrSequence,
) => {
    const workerUrl = new URL(
        '/external-chrome-ceremony-worker.mjs',
        globalThis.location.origin,
    );
    workerUrl.searchParams.set('boundary', boundary);
    const worker = new Worker(workerUrl, { type: 'module' });
    const nextMessage = () =>
        new Promise((resolve, reject) => {
            const onError = () => {
                worker.removeEventListener('message', onMessage);
                reject(new Error('The crash-boundary worker failed.'));
            };
            const onMessage = (event) => {
                worker.removeEventListener('error', onError);
                resolve(event.data);
            };
            worker.addEventListener('error', onError, { once: true });
            worker.addEventListener('message', onMessage, { once: true });
        });
    try {
        const initializeRequest = {
            input: workerInitialization(configuration),
            operation: 'initialize',
            requestId: 1,
        };
        worker.postMessage(
            initializeRequest,
            workerTransferables(initializeRequest),
        );
        const initialization = await nextMessage();
        if (
            typeof initialization !== 'object' ||
            initialization === null ||
            initialization.requestId !== 1 ||
            initialization.ok !== true
        ) {
            throw new Error('The crash-boundary worker did not initialize.');
        }
        const iterator =
            requestOrSequence?.[Symbol.asyncIterator] === undefined
                ? undefined
                : requestOrSequence[Symbol.asyncIterator]();
        let current =
            iterator === undefined
                ? { done: false, value: requestOrSequence }
                : await iterator.next();
        if (current.done) {
            throw new Error('The crash-boundary request sequence is empty.');
        }
        let requestId = 2;
        let message;
        while (true) {
            const following =
                iterator === undefined
                    ? { done: true, value: undefined }
                    : await iterator.next();
            const operationRequest = {
                ...current.value,
                requestId,
            };
            worker.postMessage(
                operationRequest,
                workerTransferables(operationRequest),
            );
            message = await nextMessage();
            if (following.done) break;
            if (
                typeof message !== 'object' ||
                message === null ||
                message.requestId !== requestId ||
                message.ok !== true
            ) {
                throw new Error(
                    'The crash-boundary worker refused an intermediate request.',
                );
            }
            current = following;
            requestId += 1;
        }
        if (
            typeof message !== 'object' ||
            message === null ||
            message.kind !== 'external-ceremony-crash-boundary' ||
            message.boundary !== boundary
        ) {
            throw new Error(
                `The worker returned before crash boundary ${boundary}.`,
            );
        }
        return { boundary, reached: true };
    } finally {
        worker.terminate();
    }
};

const fetchRoster = (configuration) => getBytes(configuration, 'roster');

const fetchPreparationParents = async (configuration) =>
    Promise.all(
        Array.from({ length: participantCount }, async (_, senderPosition) => ({
            body: await getBytes(
                configuration,
                `preparation/${String(senderPosition)}/parent-body`,
            ),
            signature: await getBytes(
                configuration,
                `preparation/${String(senderPosition)}/parent-signature`,
            ),
        })),
    );

const fetchSources = async (configuration) =>
    Promise.all(
        configuration.sourceDeclarations.map(async (declaration, position) => ({
            body: await getBytes(
                configuration,
                `source/${String(position)}/body`,
            ),
            declaration,
            signature: await getBytes(
                configuration,
                `source/${String(position)}/signature`,
            ),
        })),
    );

const fetchFinalitySignatures = async (configuration) =>
    Promise.all(
        Array.from({ length: 8 }, async (_, signerPosition) => ({
            signature: await getBytes(
                configuration,
                `finality/${String(signerPosition)}/signature`,
            ),
            signerPosition,
        })),
    );

const fetchActivationInventory = async (configuration) => {
    const manifests = [];
    const activationSignatures = [];
    for (
        let participantPosition = 0;
        participantPosition < participantCount;
        participantPosition += 1
    ) {
        manifests.push(
            await getBytes(
                configuration,
                `activation/${String(participantPosition)}/manifest`,
            ),
        );
        activationSignatures.push(
            await getBytes(
                configuration,
                `activation/${String(participantPosition)}/signature`,
            ),
        );
    }
    return { activationSignatures, manifests };
};

const fetchParticipantChunk = (
    configuration,
    chunkOrdinal,
    chunkParticipantPosition,
) =>
    getBytes(
        configuration,
        `activation/${String(chunkParticipantPosition)}/chunk/${String(chunkOrdinal)}`,
    );

const observePayloadChunk = (metrics, chunk) => {
    metrics.maximumLiveProtocolByteLength = Math.max(
        metrics.maximumLiveProtocolByteLength,
        chunk.byteLength,
    );
    metrics.accountedMaximumResidentPayloadChunkCount = Math.max(
        metrics.accountedMaximumResidentPayloadChunkCount,
        2,
    );
};

const evaluatePaddedTallyChunkStream = async (
    client,
    configuration,
    metrics,
    chunkOrdinal,
    options = {},
) => {
    const participantPositionEnd =
        options.participantPositionEnd ?? participantCount;
    const corruptParticipantPositions = new Set(
        options.corruptParticipantPositions ?? [],
    );
    let progress;
    for (
        let chunkParticipantPosition = 0;
        chunkParticipantPosition < participantPositionEnd;
        chunkParticipantPosition += 1
    ) {
        const chunk = await fetchParticipantChunk(
            configuration,
            chunkOrdinal,
            chunkParticipantPosition,
        );
        observePayloadChunk(metrics, chunk);
        if (corruptParticipantPositions.has(chunkParticipantPosition)) {
            chunk[250] ^= 1;
        }
        progress = await client.evaluatePaddedTallyChunk(
            actionContext(configuration),
            chunkOrdinal,
            chunkParticipantPosition,
            chunk,
        );
        if (
            chunkParticipantPosition + 1 < participantCount &&
            (progress.kind !== 'pending' ||
                progress.chunkOrdinal !== chunkOrdinal ||
                progress.nextChunkOrdinal !== chunkOrdinal ||
                progress.nextParticipantPosition !==
                    chunkParticipantPosition + 1)
        ) {
            throw new Error(
                'The participant chunk stream advanced before the complete roster arrived.',
            );
        }
    }
    if (progress === undefined) {
        throw new Error('The participant chunk stream produced no progress.');
    }
    return progress;
};

const evaluationCrashRequestSequence = async function* (
    configuration,
    metrics,
    chunkOrdinal,
) {
    for (
        let chunkParticipantPosition = 0;
        chunkParticipantPosition < participantCount;
        chunkParticipantPosition += 1
    ) {
        const chunk = await fetchParticipantChunk(
            configuration,
            chunkOrdinal,
            chunkParticipantPosition,
        );
        observePayloadChunk(metrics, chunk);
        yield {
            input: {
                ...actionContext(configuration),
                chunk,
                chunkParticipantPosition,
                expectedChunkOrdinal: chunkOrdinal,
            },
            operation: 'evaluate-padded-tally-chunk',
        };
    }
};

const publishPreparation = async (configuration, metrics) => {
    setStatus('reading the retained join credential');
    const credential = await readCredential(configuration);
    setStatus('reading the frozen roster');
    const canonicalRosterBytes = await fetchRoster(configuration);
    const client = await openWorkerClient(configuration);
    try {
        setStatus('creating the participant preparation package');
        const startedAt = performance.now();
        const publication = await client.createPreparationPackage(
            actionContext(configuration),
            canonicalRosterBytes,
            credential.signingSecretKey,
            credential.mailboxDecapsulationKey,
            preparationAttempt,
        );
        metrics.intervals.push({
            elapsedMilliseconds: performance.now() - startedAt,
            name: 'create preparation package',
        });
        await putBytes(
            configuration,
            `preparation/${String(configuration.participantPosition)}/parent-body`,
            publication.parentBody,
        );
        await putBytes(
            configuration,
            `preparation/${String(configuration.participantPosition)}/parent-signature`,
            publication.parentSignature,
        );
        let remoteBodyIndex = 0;
        for (
            let recipientPosition = 0;
            recipientPosition < participantCount;
            recipientPosition += 1
        ) {
            if (recipientPosition === configuration.participantPosition)
                continue;
            const privateBody = publication.privateBodies[remoteBodyIndex];
            if (!(privateBody instanceof Uint8Array)) {
                throw new Error(
                    'The preparation package omitted a private body.',
                );
            }
            await putBytes(
                configuration,
                `preparation/${String(configuration.participantPosition)}/private/${String(recipientPosition)}`,
                privateBody,
            );
            remoteBodyIndex += 1;
        }
        await deleteCredential();
        metrics.publication = {
            parentBodyByteLength: publication.parentBody.byteLength,
            parentSignatureByteLength: publication.parentSignature.byteLength,
            privateBodyByteLengths: publication.privateBodies.map(
                (body) => body.byteLength,
            ),
        };
    } finally {
        credential.signingSecretKey.fill(0);
        credential.mailboxDecapsulationKey.fill(0);
        client.close();
    }
};

const runJoin = async (configuration, metrics) => {
    const kernel = await instantiateConstructionKernelCommandRuntime(
        new URL(
            '/candidate/dist/sealed-lattice-kernel.wasm',
            globalThis.location.origin,
        ),
        { expectedKernelSha256Hex: configuration.kernelSha256Hex },
    );
    const actionSignature = openActionSignatureRuntime(kernel);
    const pairEncryption = openPairEncryptionRuntime(kernel);
    const signing = actionSignature.generateKeyPair(
        crypto.getRandomValues(
            new Uint8Array(actionSignatureKeyGenerationRandomnessByteLength),
        ),
    );
    const mailbox = pairEncryption.generateKeyPair(
        crypto.getRandomValues(
            new Uint8Array(pairEncryptionKeyGenerationRandomnessByteLength),
        ),
    );
    await storeCredential(
        configuration,
        signing.secretKey,
        mailbox.decryptionKey,
    );
    await putBytes(
        configuration,
        `roster-key/${String(configuration.participantPosition)}/signing`,
        signing.verificationKey,
    );
    await putBytes(
        configuration,
        `roster-key/${String(configuration.participantPosition)}/mailbox`,
        mailbox.encryptionKey,
    );
    signing.secretKey.fill(0);
    mailbox.decryptionKey.fill(0);
    metrics.kernelResources = kernel.measureResources();
    if (configuration.participantPosition === participantCount - 1) {
        const publicKeys = [];
        for (let position = 0; position < participantCount; position += 1) {
            publicKeys.push({
                mailboxEncapsulationKey: await getBytes(
                    configuration,
                    `roster-key/${String(position)}/mailbox`,
                ),
                signingVerificationKey: await getBytes(
                    configuration,
                    `roster-key/${String(position)}/signing`,
                ),
            });
        }
        const roster = openRosterRuntime(kernel).encode(publicKeys);
        await putBytes(configuration, 'roster', roster.canonicalBytes);
        metrics.rosterIdentityHex = bytesToHex(roster.rosterIdentity);
        await publishPreparation(configuration, metrics);
    }
};

const consumePreparations = async (configuration, metrics, crashBoundary) => {
    const canonicalRosterBytes = await fetchRoster(configuration);
    const preparationParents = await fetchPreparationParents(configuration);
    if (crashBoundary === 'preparation-consume') {
        const senderPosition = configuration.participantPosition === 0 ? 1 : 0;
        const parent = preparationParents[senderPosition];
        const privateBody = await getBytes(
            configuration,
            `preparation/${String(senderPosition)}/private/${String(configuration.participantPosition)}`,
        );
        return {
            canonicalRosterBytes,
            crashed: await runUntilCrashBoundary(configuration, crashBoundary, {
                input: {
                    ...actionContext(configuration),
                    canonicalRosterBytes,
                    parentBody: parent.body,
                    parentSignature: parent.signature,
                    preparationAttempt,
                    privateBody,
                },
                operation: 'consume-private-preparation',
            }),
            preparationParents,
        };
    }
    const client = await openWorkerClient(configuration);
    try {
        const statuses = [];
        for (
            let senderPosition = 0;
            senderPosition < participantCount;
            senderPosition += 1
        ) {
            if (senderPosition === configuration.participantPosition) continue;
            const parent = preparationParents[senderPosition];
            const privateBody = await getBytes(
                configuration,
                `preparation/${String(senderPosition)}/private/${String(configuration.participantPosition)}`,
            );
            const consumption = await client.consumePrivatePreparation(
                actionContext(configuration),
                canonicalRosterBytes,
                preparationAttempt,
                parent.body,
                parent.signature,
                privateBody,
            );
            statuses.push(consumption.status);
        }
        metrics.preparationConsumptionStatuses = statuses;
    } finally {
        client.close();
    }
    return { canonicalRosterBytes, preparationParents };
};

const sourceChoice = (configuration) => {
    if (configuration.ballot?.declaration === 'abstain') {
        return { declaration: 'abstain' };
    }
    if (
        configuration.ballot?.declaration !== 'submit' ||
        !Array.isArray(configuration.ballot.scoreEncodings) ||
        configuration.ballot.scoreEncodings.length !== participantCount
    ) {
        throw new TypeError('The source visit ballot is invalid.');
    }
    return {
        declaration: 'submit',
        scoreEncodings: Uint8Array.from(configuration.ballot.scoreEncodings),
    };
};

const runSource = async (configuration, metrics) => {
    const consumed = await consumePreparations(
        configuration,
        metrics,
        configuration.crashBoundary,
    );
    if (consumed.crashed !== undefined) {
        metrics.crash = consumed.crashed;
        return;
    }
    const choice = sourceChoice(configuration);
    if (configuration.crashBoundary === 'source-bind') {
        metrics.crash = await runUntilCrashBoundary(
            configuration,
            'source-bind',
            {
                input: {
                    ...actionContext(configuration),
                    canonicalRosterBytes: consumed.canonicalRosterBytes,
                    choice,
                    preparationAttempt,
                    preparationParents: consumed.preparationParents,
                },
                operation: 'create-source-package',
            },
        );
        return;
    }
    const client = await openWorkerClient(configuration);
    try {
        if (configuration.expectPendingSourceRefusal === true) {
            metrics.pendingSourceRefusal = await expectRefusal(() =>
                client.createSourcePackage(
                    actionContext(configuration),
                    consumed.canonicalRosterBytes,
                    preparationAttempt,
                    consumed.preparationParents,
                    choice,
                ),
            );
            return;
        }
        const publication = await client.createSourcePackage(
            actionContext(configuration),
            consumed.canonicalRosterBytes,
            preparationAttempt,
            consumed.preparationParents,
            choice,
        );
        await putBytes(
            configuration,
            `source/${String(configuration.participantPosition)}/body`,
            publication.sourceBody,
        );
        await putBytes(
            configuration,
            `source/${String(configuration.participantPosition)}/signature`,
            publication.sourceSignature,
        );
        metrics.publication = {
            sourceBodyByteLength: publication.sourceBody.byteLength,
            sourceSignatureByteLength: publication.sourceSignature.byteLength,
        };
        if (configuration.probeSourceConflict === true) {
            const alternateChoice =
                choice.declaration === 'abstain'
                    ? {
                          declaration: 'submit',
                          scoreEncodings: new Uint8Array(participantCount).fill(
                              1,
                          ),
                      }
                    : { declaration: 'abstain' };
            metrics.sourceConflict = await expectRefusal(() =>
                client.createSourcePackage(
                    actionContext(configuration),
                    consumed.canonicalRosterBytes,
                    preparationAttempt,
                    consumed.preparationParents,
                    alternateChoice,
                ),
            );
        }
    } finally {
        client.close();
    }
};

const expectRefusal = async (operation) => {
    try {
        await operation();
    } catch (error) {
        return {
            message: error instanceof Error ? error.message : String(error),
            name: error instanceof Error ? error.name : 'UnknownError',
        };
    }
    throw new Error('The hostile input was accepted unexpectedly.');
};

const runFinality = async (configuration, metrics) => {
    const canonicalRosterBytes = await fetchRoster(configuration);
    const sources = await fetchSources(configuration);
    const client = await openWorkerClient(configuration);
    try {
        if (configuration.probeCorruptSource === true) {
            const corruptSources = sources.map((source) => ({
                ...source,
                body: Uint8Array.from(source.body),
            }));
            corruptSources[2].body[corruptSources[2].body.byteLength - 1] ^= 1;
            metrics.corruptSourceRefusal = await expectRefusal(() =>
                client.createFinalitySignature(
                    actionContext(configuration),
                    canonicalRosterBytes,
                    preparationAttempt,
                    corruptSources,
                    configuration.topCount,
                ),
            );
        }
        const finality = await client.createFinalitySignature(
            actionContext(configuration),
            canonicalRosterBytes,
            preparationAttempt,
            sources,
            configuration.topCount,
        );
        await putBytes(
            configuration,
            `finality/${String(configuration.participantPosition)}/target-body`,
            finality.targetBody,
        );
        await putBytes(
            configuration,
            `finality/${String(configuration.participantPosition)}/target-identity`,
            finality.targetIdentity,
        );
        await putBytes(
            configuration,
            `finality/${String(configuration.participantPosition)}/signature`,
            finality.finalitySignature,
        );
        metrics.finality = {
            sourceSubmissionBitmap: finality.sourceSubmissionBitmap,
            targetIdentityHex: bytesToHex(finality.targetIdentity),
            targetKind: finality.targetKind,
            topCount: finality.topCount,
        };
        if (configuration.probeFinalityConflict === true) {
            metrics.finalityConflict = await expectRefusal(() =>
                client.createFinalitySignature(
                    actionContext(configuration),
                    canonicalRosterBytes,
                    preparationAttempt,
                    [...sources].reverse(),
                    configuration.topCount,
                ),
            );
        }
    } finally {
        client.close();
    }
};

const generationInput = async (configuration) => ({
    ...actionContext(configuration),
    canonicalRosterBytes: await fetchRoster(configuration),
    finalitySignatures: await fetchFinalitySignatures(configuration),
    preparationAttempt,
    preparationParents: await fetchPreparationParents(configuration),
    sources: await fetchSources(configuration),
    topCount: configuration.topCount,
});

const publishGeneratedChunk = async (configuration, generated, metrics) => {
    await putBytes(
        configuration,
        `activation/${String(configuration.participantPosition)}/chunk/${String(generated.chunkOrdinal)}`,
        generated.chunk,
    );
    observePayloadChunk(metrics, generated.chunk);
    if (generated.status === 'complete') {
        await putBytes(
            configuration,
            `activation/${String(configuration.participantPosition)}/manifest`,
            generated.manifest,
        );
        await putBytes(
            configuration,
            `activation/${String(configuration.participantPosition)}/signature`,
            generated.activationSignature,
        );
        metrics.manifestIdentityHex = bytesToHex(generated.manifestIdentity);
    }
};

const runActivation = async (configuration, metrics) => {
    const input = await generationInput(configuration);
    if (configuration.crashBoundary === 'tally-generation-initialize') {
        metrics.crash = await runUntilCrashBoundary(
            configuration,
            configuration.crashBoundary,
            { input, operation: 'initialize-padded-tally-generation' },
        );
        return;
    }
    let client = await openWorkerClient(configuration);
    try {
        const initialization = await client.initializePaddedTallyGeneration(
            actionContext(configuration),
            input.canonicalRosterBytes,
            preparationAttempt,
            input.preparationParents,
            input.sources,
            input.finalitySignatures,
            configuration.topCount,
        );
        metrics.kernelResources = initialization.resources;
        metrics.plan = {
            chunkCount: initialization.plan.chunks.length,
            logicalPayloadByteLength:
                initialization.plan.logicalPayloadByteLength,
            outputCount: initialization.plan.outputCount,
            topCount: initialization.plan.topCount,
        };
        const lastChunkOrdinal = initialization.plan.chunks.length - 1;
        const firstChunkOrdinal = requireInteger(
            configuration.startChunkOrdinal ?? 0,
            0,
            lastChunkOrdinal,
            'startChunkOrdinal',
        );
        if (configuration.crashBoundary === 'tally-chunk-persist') {
            client.close();
            client = undefined;
            metrics.crash = await runUntilCrashBoundary(
                configuration,
                configuration.crashBoundary,
                {
                    input: {
                        ...actionContext(configuration),
                        expectedChunkOrdinal: firstChunkOrdinal,
                    },
                    operation: 'create-padded-tally-chunk',
                },
            );
            return;
        }
        const stopBeforePublication =
            configuration.crashBoundary === 'tally-activation-publish';
        const operationEnd = stopBeforePublication
            ? lastChunkOrdinal
            : lastChunkOrdinal + 1;
        for (
            let chunkOrdinal = firstChunkOrdinal;
            chunkOrdinal < operationEnd;
            chunkOrdinal += 1
        ) {
            const generated = await client.createPaddedTallyChunk(
                actionContext(configuration),
                chunkOrdinal,
            );
            metrics.kernelResources =
                generated.resources ?? metrics.kernelResources;
            await publishGeneratedChunk(configuration, generated, metrics);
        }
        if (stopBeforePublication) {
            client.close();
            client = undefined;
            metrics.crash = await runUntilCrashBoundary(
                configuration,
                configuration.crashBoundary,
                {
                    input: {
                        ...actionContext(configuration),
                        expectedChunkOrdinal: lastChunkOrdinal,
                    },
                    operation: 'create-padded-tally-chunk',
                },
            );
        }
    } finally {
        client?.close();
    }
};

const evaluationInput = async (configuration) => {
    const activation = await fetchActivationInventory(configuration);
    return {
        ...actionContext(configuration),
        activationSignatures: activation.activationSignatures,
        canonicalRosterBytes: await fetchRoster(configuration),
        finalitySignatures: await fetchFinalitySignatures(configuration),
        manifests: activation.manifests,
    };
};

const snapshotStore = async (databaseName, storeName) => {
    const database = await openDatabase(databaseName);
    try {
        const transaction = database.transaction(storeName, 'readonly');
        const records = await requestResult(
            transaction.objectStore(storeName).getAll(),
        );
        await transactionCompletion(transaction);
        if (!Array.isArray(records)) {
            throw new Error(`Store ${storeName} did not return records.`);
        }
        return structuredClone(records);
    } finally {
        database.close();
    }
};

const restoreStore = async (databaseName, storeName, records) => {
    const database = await openDatabase(databaseName);
    try {
        const transaction = database.transaction(storeName, 'readwrite', {
            durability: 'strict',
        });
        const store = transaction.objectStore(storeName);
        store.clear();
        for (const record of records) store.put(structuredClone(record));
        await transactionCompletion(transaction);
    } finally {
        database.close();
    }
};

const runTransportCancellationProbe = async (configuration) => {
    const controller = new AbortController();
    const pending = fetch(
        `${relayUrl(configuration, 'probe/delayed-missing')}?delay=2000`,
        {
            cache: 'no-store',
            headers: requestHeaders(configuration),
            signal: controller.signal,
        },
    );
    setTimeout(() => controller.abort(), 20);
    try {
        await pending;
    } catch (error) {
        if (error instanceof DOMException && error.name === 'AbortError') {
            return { name: error.name, refused: true };
        }
        throw error;
    }
    throw new Error('The cancelled relay request completed unexpectedly.');
};

const runEvaluationRepair = async (configuration, metrics) => {
    const input = await evaluationInput(configuration);
    let client = await openWorkerClient(configuration);
    try {
        const initialization = await client.initializePaddedTallyEvaluation(
            actionContext(configuration),
            input.canonicalRosterBytes,
            input.finalitySignatures,
            input.manifests,
            input.activationSignatures,
        );
        metrics.kernelResources = initialization.resources;
        const before = await snapshotStore(
            configuration.databaseName,
            'evaluations',
        );
        const first = await evaluatePaddedTallyChunkStream(
            client,
            configuration,
            metrics,
            0,
        );
        metrics.kernelResources = first.resources;
        const replay = await evaluatePaddedTallyChunkStream(
            client,
            configuration,
            metrics,
            0,
        );
        if (JSON.stringify(replay) !== JSON.stringify(first)) {
            throw new Error(
                'A byte-identical evaluation replay changed progress.',
            );
        }
        metrics.alternateContinuationRefusal = await expectRefusal(() =>
            evaluatePaddedTallyChunkStream(client, configuration, metrics, 0, {
                corruptParticipantPositions: [4],
            }),
        );
        client.close();
        client = undefined;
        const after = await snapshotStore(
            configuration.databaseName,
            'evaluations',
        );
        await restoreStore(configuration.databaseName, 'evaluations', before);
        const rollbackClient = await openWorkerClient(configuration);
        try {
            metrics.rollbackRefusal = await expectRefusal(() =>
                evaluatePaddedTallyChunkStream(
                    rollbackClient,
                    configuration,
                    metrics,
                    1,
                ),
            );
        } finally {
            rollbackClient.close();
        }
        await restoreStore(configuration.databaseName, 'evaluations', after);
        const restoredClient = await openWorkerClient(configuration);
        try {
            const withheld = await evaluatePaddedTallyChunkStream(
                restoredClient,
                configuration,
                metrics,
                1,
                { participantPositionEnd: participantCount - 1 },
            );
            if (
                withheld.kind !== 'pending' ||
                withheld.nextChunkOrdinal !== 1 ||
                withheld.nextParticipantPosition !== participantCount - 1
            ) {
                throw new Error(
                    'A selectively withheld participant chunk did not leave evaluation pending.',
                );
            }
            metrics.withholdingPending = {
                chunkOrdinal: 1,
                nextParticipantPosition: participantCount - 1,
                pending: true,
            };
        } finally {
            restoredClient.close();
        }
        metrics.transportCancellation =
            await runTransportCancellationProbe(configuration);
        metrics.nextChunkOrdinal = 1;
    } finally {
        client?.close();
    }
};

const terminalSummary = (terminal) => ({
    acceptedBallotAuthorshipBitmap: terminal.acceptedBallotAuthorshipBitmap,
    batchIdentityHex:
        'batchIdentity' in terminal
            ? bytesToHex(terminal.batchIdentity)
            : undefined,
    kind: terminal.kind,
    orderedOptionPositions:
        terminal.kind === 'result'
            ? [...terminal.orderedOptionPositions]
            : undefined,
    terminalIdentityHex:
        'terminalIdentity' in terminal
            ? bytesToHex(terminal.terminalIdentity)
            : undefined,
    terminalPath:
        terminal.kind === 'no-result' ? terminal.terminalPath : undefined,
});

const publishTerminal = async (configuration, terminal) => {
    if ('terminalBody' in terminal) {
        await putBytes(
            configuration,
            `terminal/${String(configuration.participantPosition)}/body`,
            terminal.terminalBody,
        );
        await putBytes(
            configuration,
            `terminal/${String(configuration.participantPosition)}/identity`,
            terminal.terminalIdentity,
        );
    }
};

const runEvaluation = async (configuration, metrics) => {
    const input = await evaluationInput(configuration);
    if (configuration.crashBoundary === 'tally-evaluation-initialize') {
        metrics.crash = await runUntilCrashBoundary(
            configuration,
            configuration.crashBoundary,
            { input, operation: 'initialize-padded-tally-evaluation' },
        );
        return;
    }
    let client = await openWorkerClient(configuration);
    try {
        const initialization = await client.initializePaddedTallyEvaluation(
            actionContext(configuration),
            input.canonicalRosterBytes,
            input.finalitySignatures,
            input.manifests,
            input.activationSignatures,
        );
        metrics.kernelResources = initialization.resources;
        const lastChunkOrdinal = initialization.plan.chunks.length - 1;
        const firstChunkOrdinal = requireInteger(
            configuration.startChunkOrdinal ?? 0,
            0,
            lastChunkOrdinal,
            'startChunkOrdinal',
        );
        if (configuration.probeCorruptManifest === true) {
            const corruptManifests = input.manifests.map((manifest) =>
                Uint8Array.from(manifest),
            );
            corruptManifests[2][corruptManifests[2].byteLength - 1] ^= 1;
            metrics.corruptManifestRefusal = await expectRefusal(() =>
                client.initializePaddedTallyEvaluation(
                    actionContext(configuration),
                    input.canonicalRosterBytes,
                    input.finalitySignatures,
                    corruptManifests,
                    input.activationSignatures,
                ),
            );
        }
        if (configuration.crashBoundary === 'tally-evaluation-step') {
            client.close();
            client = undefined;
            metrics.crash = await runUntilCrashBoundary(
                configuration,
                configuration.crashBoundary,
                evaluationCrashRequestSequence(
                    configuration,
                    metrics,
                    firstChunkOrdinal,
                ),
            );
            return;
        }
        const stopBeforeTerminal =
            configuration.crashBoundary === 'tally-terminal-persist';
        const operationEnd = stopBeforeTerminal
            ? lastChunkOrdinal
            : lastChunkOrdinal + 1;
        let terminal;
        for (
            let chunkOrdinal = firstChunkOrdinal;
            chunkOrdinal < operationEnd;
            chunkOrdinal += 1
        ) {
            if (
                configuration.probeThreeCorruptChunks === true &&
                chunkOrdinal === 0
            ) {
                metrics.threeCorruptChunkRefusal = await expectRefusal(() =>
                    evaluatePaddedTallyChunkStream(
                        client,
                        configuration,
                        metrics,
                        chunkOrdinal,
                        { corruptParticipantPositions: [0, 1, 2] },
                    ),
                );
            }
            const progress = await evaluatePaddedTallyChunkStream(
                client,
                configuration,
                metrics,
                chunkOrdinal,
            );
            metrics.kernelResources = progress.resources;
            if (progress.kind !== 'pending') terminal = progress;
        }
        if (stopBeforeTerminal) {
            client.close();
            client = undefined;
            metrics.crash = await runUntilCrashBoundary(
                configuration,
                configuration.crashBoundary,
                evaluationCrashRequestSequence(
                    configuration,
                    metrics,
                    lastChunkOrdinal,
                ),
            );
            return;
        }
        if (terminal === undefined) {
            terminal = await client.readTallyResult(
                actionContext(configuration),
            );
        }
        const restored = await client.readTallyResult(
            actionContext(configuration),
        );
        if (
            JSON.stringify(terminalSummary(restored)) !==
            JSON.stringify(terminalSummary(terminal))
        ) {
            throw new Error('Restored result retrieval changed the terminal.');
        }
        await publishTerminal(configuration, terminal);
        metrics.terminal = terminalSummary(terminal);
    } finally {
        client?.close();
    }
};

const runNoResult = async (configuration, metrics) => {
    const client = await openWorkerClient(configuration);
    try {
        const terminal = await client.finalizeNoResult(
            actionContext(configuration),
            await fetchRoster(configuration),
            preparationAttempt,
            await fetchSources(configuration),
            await fetchFinalitySignatures(configuration),
            configuration.topCount,
        );
        const restored = await client.readTallyResult(
            actionContext(configuration),
        );
        if (
            JSON.stringify(terminalSummary(restored)) !==
            JSON.stringify(terminalSummary(terminal))
        ) {
            throw new Error('The restored source-empty result changed.');
        }
        metrics.kernelResources = terminal.resources;
        metrics.terminal = terminalSummary(terminal);
    } finally {
        client.close();
    }
};

const runPressure = async (configuration, metrics) => {
    const requestedByteLength = requireInteger(
        configuration.pressureByteLength ?? 0,
        0,
        268_435_456,
        'pressureByteLength',
    );
    if (requestedByteLength === 0) return;
    const database = await openCredentialDatabase();
    try {
        const chunk = new Uint8Array(pressureChunkByteLength);
        for (let offset = 0; offset < chunk.byteLength; offset += 65_536) {
            crypto.getRandomValues(
                chunk.subarray(
                    offset,
                    Math.min(offset + 65_536, chunk.byteLength),
                ),
            );
        }
        let writtenByteLength = 0;
        let ordinal = 0;
        while (writtenByteLength < requestedByteLength) {
            const byteLength = Math.min(
                chunk.byteLength,
                requestedByteLength - writtenByteLength,
            );
            const transaction = database.transaction(
                pressureStoreName,
                'readwrite',
                { durability: 'strict' },
            );
            transaction
                .objectStore(pressureStoreName)
                .put(chunk.slice(0, byteLength), ordinal);
            await transactionCompletion(transaction);
            writtenByteLength += byteLength;
            ordinal += 1;
        }
        metrics.quotaPressureByteLength = writtenByteLength;
        metrics.storageUnderQuotaPressure = await storageEstimate();
        const clear = database.transaction(pressureStoreName, 'readwrite', {
            durability: 'strict',
        });
        clear.objectStore(pressureStoreName).clear();
        await transactionCompletion(clear);
    } finally {
        database.close();
    }
};

const runStateLossProbe = async (configuration, metrics) => {
    const database = await openDatabase(configuration.databaseName);
    try {
        const transaction = database.transaction('evaluations', 'readwrite', {
            durability: 'strict',
        });
        const store = transaction.objectStore('evaluations');
        const keys = await requestResult(store.getAllKeys());
        if (!Array.isArray(keys) || keys.length !== 1) {
            throw new Error('The state-loss probe found no unique evaluation.');
        }
        store.delete(keys[0]);
        await transactionCompletion(transaction);
    } finally {
        database.close();
    }
    const client = await openWorkerClient(configuration);
    try {
        metrics.stateLossRefusal = await expectRefusal(() =>
            client.readTallyResult(actionContext(configuration)),
        );
    } finally {
        client.close();
    }
};

const cleanupParticipant = async (configuration) => {
    await deleteDatabase(configuration.databaseName);
    await deleteDatabase(credentialDatabaseName);
};

const runVisit = async (rawConfiguration) => {
    const configuration = requireConfiguration(rawConfiguration);
    setStatus(
        `${configuration.action} for participant ${String(configuration.participantPosition)}`,
    );
    const startedAt = performance.now();
    const platform = await requirePlatform();
    const storageBefore = await storageEstimate();
    const metrics = {
        action: configuration.action,
        accountedMaximumResidentPayloadChunkCount: 0,
        intervals: [],
        maximumLiveProtocolByteLength: 0,
        participantPosition: configuration.participantPosition,
        platform,
        storageBefore,
    };
    if (!platform.persistedAfter) {
        if (configuration.action !== 'probe-missing-persistence') {
            throw new Error('Persistent storage was not granted.');
        }
        metrics.missingPersistenceRefusal = {
            message:
                'The participant preflight refused before generating secrets because persistent storage was unavailable.',
            name: 'MissingPersistence',
        };
    } else {
        switch (configuration.action) {
            case 'join':
                await runJoin(configuration, metrics);
                break;
            case 'prepare':
                await publishPreparation(configuration, metrics);
                break;
            case 'source':
                await runSource(configuration, metrics);
                break;
            case 'finality':
                await runFinality(configuration, metrics);
                break;
            case 'activation':
                await runActivation(configuration, metrics);
                break;
            case 'evaluation':
                await runEvaluation(configuration, metrics);
                break;
            case 'evaluation-repair':
                await runEvaluationRepair(configuration, metrics);
                break;
            case 'no-result':
                await runNoResult(configuration, metrics);
                break;
            case 'state-loss-probe':
                await runStateLossProbe(configuration, metrics);
                break;
            case 'reclaim':
                metrics.coldReclaimObservation = await storageEstimate();
                break;
            default:
                throw new Error(
                    `Unknown visit action ${configuration.action}.`,
                );
        }
        await runPressure(configuration, metrics);
        if (configuration.cleanup === true) {
            await cleanupParticipant(configuration);
        }
    }
    if (metrics.kernelResources !== undefined) {
        metrics.maximumCopiedPayloadBufferByteLength = Math.max(
            metrics.maximumLiveProtocolByteLength,
            metrics.kernelResources.maximumRequestByteLength,
            metrics.kernelResources.maximumResponseByteLength,
        );
        metrics.accountedJavaScriptWasmOverlapByteLength =
            2 * metrics.maximumLiveProtocolByteLength +
            metrics.kernelResources.maximumRequestByteLength +
            metrics.kernelResources.maximumResponseByteLength +
            metrics.kernelResources.wasmMemoryByteLength;
    }
    metrics.storageAfter = await storageEstimate();
    metrics.totalForegroundMilliseconds = performance.now() - startedAt;
    metrics.longestUninterruptedMilliseconds = Math.max(
        0,
        ...metrics.intervals.map((interval) => interval.elapsedMilliseconds),
    );
    setStatus('Complete.');
    return metrics;
};

globalThis.runExternalChromeCeremonyVisit = runVisit;

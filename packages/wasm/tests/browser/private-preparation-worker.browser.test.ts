import { afterEach, describe, expect, it } from 'vitest';

import {
    actionSignatureKeyGenerationRandomnessByteLength,
    openActionSignatureRuntime,
} from '../../src/action-signature-runtime.js';
import { instantiateConstructionKernelCommandRuntime } from '../../src/foundation-kernel/kernel-runtime.js';
import {
    openPairEncryptionRuntime,
    pairEncryptionKeyGenerationRandomnessByteLength,
} from '../../src/pair-encryption-runtime.js';
import { actionSignatureCarrierByteLength } from '../../src/preparation-parent-runtime.js';
import { PrivatePreparationWorkerClient } from '../../src/private-preparation-worker-client.js';
import type {
    PrivatePreparationActionContext,
    PrivatePreparationWorkerRequest,
    PrivatePreparationWorkerResponse,
    PublishedFinalityPackage,
    PublishedPreparationPackage,
    PublishedReducedActivationPackage,
    PublishedSourcePackage,
} from '../../src/private-preparation-worker-protocol.js';
import { openRosterRuntime } from '../../src/roster-runtime.js';
import {
    abstentionSourceBodyByteLength,
    submittedSourceBodyByteLength,
} from '../../src/source-runtime.js';

const participantCount = 10;
const preparationAttempt = 7;
const runtimeIdentity = new Uint8Array(64).fill(0x11);
const candidateBuildIdentity = new Uint8Array(64).fill(0x22);
const actionProposalIdentity = new Uint8Array(64).fill(0x33);
const actionDefinitionIdentity = new Uint8Array(64).fill(0x34);
const predecessorIdentity = new Uint8Array(64).fill(0x44);
const kernelUrl = new URL(
    '/packages/wasm/dist/sealed-lattice-kernel.wasm',
    window.location.origin,
);
const ordinaryWorkerUrl = new URL(
    './fixtures/private-preparation-test-worker.ts',
    import.meta.url,
);
const crashWorkerUrl = new URL(
    './fixtures/private-preparation-crash-worker.ts',
    import.meta.url,
);
const sourceCrashWorkerUrl = new URL(
    './fixtures/private-preparation-source-crash-worker.ts',
    import.meta.url,
);
const activationAllocationCrashWorkerUrl = new URL(
    './fixtures/private-preparation-activation-allocation-crash-worker.ts',
    import.meta.url,
);
const activationBodyCrashWorkerUrl = new URL(
    './fixtures/private-preparation-activation-body-crash-worker.ts',
    import.meta.url,
);
const activationPublicationCrashWorkerUrl = new URL(
    './fixtures/private-preparation-activation-publication-crash-worker.ts',
    import.meta.url,
);

const openClients = new Set<PrivatePreparationWorkerClient>();
const databaseNames = new Set<string>();

const actionContext = (
    participantPosition: number,
): PrivatePreparationActionContext => ({
    actionProposalIdentity,
    actionDefinitionIdentity,
    predecessorIdentity,
    participantPosition,
});

const databaseName = (
    runIdentity: string,
    participantPosition: number,
): string =>
    `sealed-lattice-worker-${runIdentity}-${String(participantPosition)}`;

const deleteDatabase = (name: string): Promise<void> =>
    new Promise((resolve, reject) => {
        const request = indexedDB.deleteDatabase(name);
        request.addEventListener('success', () => resolve());
        request.addEventListener('error', () =>
            reject(new Error(`Failed to delete test database ${name}.`)),
        );
        request.addEventListener('blocked', () =>
            reject(new Error(`Test database ${name} remained open.`)),
        );
    });

const openDatabase = (name: string): Promise<IDBDatabase> =>
    new Promise((resolve, reject) => {
        const request = indexedDB.open(name);
        request.addEventListener('success', () => resolve(request.result));
        request.addEventListener('error', () =>
            reject(new Error(`Failed to open test database ${name}.`)),
        );
    });

const transactionCompletion = (transaction: IDBTransaction): Promise<void> =>
    new Promise((resolve, reject) => {
        transaction.addEventListener('complete', () => resolve());
        transaction.addEventListener('abort', () =>
            reject(new Error('The test database transaction was aborted.')),
        );
        transaction.addEventListener('error', () =>
            reject(new Error('The test database transaction failed.')),
        );
    });

const readRawActivationRecord = async (
    name: string,
    identifier: string,
): Promise<unknown> => {
    const database = await openDatabase(name);
    try {
        const transaction = database.transaction('activations', 'readonly');
        const request = transaction.objectStore('activations').get(identifier);
        const result = await new Promise<unknown>((resolve, reject) => {
            request.addEventListener('success', () => resolve(request.result));
            request.addEventListener('error', () =>
                reject(new Error('Failed to read raw activation state.')),
            );
        });
        await transactionCompletion(transaction);
        return result;
    } finally {
        database.close();
    }
};

const restoreRawActivationRecord = async (
    name: string,
    record: unknown,
): Promise<void> => {
    const database = await openDatabase(name);
    try {
        const transaction = database.transaction('activations', 'readwrite', {
            durability: 'strict',
        });
        transaction.objectStore('activations').put(record);
        await transactionCompletion(transaction);
    } finally {
        database.close();
    }
};

const deleteRawActivationRecord = async (
    name: string,
    identifier: string,
): Promise<void> => {
    const database = await openDatabase(name);
    try {
        const transaction = database.transaction('activations', 'readwrite', {
            durability: 'strict',
        });
        transaction.objectStore('activations').delete(identifier);
        await transactionCompletion(transaction);
    } finally {
        database.close();
    }
};

const bytesToHex = (bytes: Uint8Array): string =>
    Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

const activationIdentifier = (participantPosition: number): string =>
    `reduced-activation.${bytesToHex(runtimeIdentity)}.${bytesToHex(
        actionProposalIdentity,
    )}.${String(participantPosition)}`;

const openClient = async (
    runIdentity: string,
    participantPosition: number,
): Promise<PrivatePreparationWorkerClient> => {
    const name = databaseName(runIdentity, participantPosition);
    databaseNames.add(name);
    const client = await PrivatePreparationWorkerClient.create(
        ordinaryWorkerUrl,
        {
            databaseName: name,
            kernelUrl: kernelUrl.toString(),
            kernelOptions: { allowUnpinnedKernel: true },
            runtimeIdentity,
            candidateBuildIdentity,
        },
    );
    openClients.add(client);
    return client;
};

const closeClient = (client: PrivatePreparationWorkerClient): void => {
    client.close();
    openClients.delete(client);
};

type CompletionRosterFixture = Readonly<{
    canonicalRosterBytes: Uint8Array;
    rosterIdentity: Uint8Array;
    credentials: readonly Readonly<{
        signingSecretKey: Uint8Array;
        mailboxDecapsulationKey: Uint8Array;
    }>[];
}>;

const createCompletionRosterFixture =
    async (): Promise<CompletionRosterFixture> => {
        const kernel = await instantiateConstructionKernelCommandRuntime(
            kernelUrl,
            {
                allowUnpinnedKernel: true,
            },
        );
        const signatureRuntime = openActionSignatureRuntime(kernel);
        const mailboxRuntime = openPairEncryptionRuntime(kernel);
        const rosterRuntime = openRosterRuntime(kernel);
        const credentials: Array<{
            signingSecretKey: Uint8Array;
            mailboxDecapsulationKey: Uint8Array;
        }> = [];
        const publicKeys = Array.from({ length: participantCount }, () => {
            const signing = signatureRuntime.generateKeyPair(
                crypto.getRandomValues(
                    new Uint8Array(
                        actionSignatureKeyGenerationRandomnessByteLength,
                    ),
                ),
            );
            const mailbox = mailboxRuntime.generateKeyPair(
                crypto.getRandomValues(
                    new Uint8Array(
                        pairEncryptionKeyGenerationRandomnessByteLength,
                    ),
                ),
            );
            credentials.push({
                signingSecretKey: signing.secretKey,
                mailboxDecapsulationKey: mailbox.decryptionKey,
            });
            return {
                signingVerificationKey: signing.verificationKey,
                mailboxEncapsulationKey: mailbox.encryptionKey,
            };
        });
        const roster = rosterRuntime.encode(publicKeys);
        return {
            canonicalRosterBytes: roster.canonicalBytes,
            rosterIdentity: roster.rosterIdentity,
            credentials,
        };
    };

const publishPreparationPackages = async (
    runIdentity: string,
    roster: CompletionRosterFixture,
): Promise<PublishedPreparationPackage[]> => {
    const packages: PublishedPreparationPackage[] = [];
    for (
        let participantPosition = 0;
        participantPosition < participantCount;
        participantPosition += 1
    ) {
        const credential = roster.credentials[participantPosition];
        if (credential === undefined) {
            throw new Error('The roster fixture omitted a credential.');
        }
        const client = await openClient(runIdentity, participantPosition);
        packages.push(
            await client.createPreparationPackage(
                actionContext(participantPosition),
                roster.canonicalRosterBytes,
                credential.signingSecretKey,
                credential.mailboxDecapsulationKey,
                preparationAttempt,
            ),
        );
        closeClient(client);
    }
    return packages;
};

const remoteBodyIndex = (
    senderPosition: number,
    recipientPosition: number,
): number =>
    recipientPosition < senderPosition
        ? recipientPosition
        : recipientPosition - 1;

const createCompletePreparation = async (
    runIdentity: string,
): Promise<
    Readonly<{
        canonicalRosterBytes: Uint8Array;
        preparationPackages: readonly PublishedPreparationPackage[];
        preparationParents: readonly Readonly<{
            body: Uint8Array;
            signature: Uint8Array;
        }>[];
    }>
> => {
    const roster = await createCompletionRosterFixture();
    const canonicalRosterBytes = roster.canonicalRosterBytes;
    const preparationPackages = await publishPreparationPackages(
        runIdentity,
        roster,
    );
    const preparationParents = preparationPackages.map((entry) => ({
        body: entry.parentBody,
        signature: entry.parentSignature,
    }));
    for (
        let recipientPosition = 0;
        recipientPosition < participantCount;
        recipientPosition += 1
    ) {
        const client = await openClient(runIdentity, recipientPosition);
        for (
            let senderPosition = 0;
            senderPosition < participantCount;
            senderPosition += 1
        ) {
            if (senderPosition === recipientPosition) {
                continue;
            }
            const privateBody =
                preparationPackages[senderPosition]?.privateBodies[
                    remoteBodyIndex(senderPosition, recipientPosition)
                ];
            const parent = preparationPackages[senderPosition];
            if (privateBody === undefined || parent === undefined) {
                throw new Error('The preparation fixture is incomplete.');
            }
            const consumption = await client.consumePrivatePreparation(
                actionContext(recipientPosition),
                canonicalRosterBytes,
                preparationAttempt,
                parent.parentBody,
                parent.parentSignature,
                privateBody,
            );
            if (consumption.status !== 'resolved') {
                throw new Error('A preparation delivery did not resolve.');
            }
        }
        closeClient(client);
    }
    return {
        canonicalRosterBytes,
        preparationPackages,
        preparationParents,
    };
};

const rawRequest = <Result>(
    worker: Worker,
    request: PrivatePreparationWorkerRequest,
): Promise<Result> =>
    new Promise((resolve, reject) => {
        const onMessage = (
            event: MessageEvent<PrivatePreparationWorkerResponse>,
        ): void => {
            const response = event.data;
            if (
                typeof response !== 'object' ||
                response === null ||
                !('requestId' in response) ||
                response.requestId !== request.requestId
            ) {
                return;
            }
            worker.removeEventListener('message', onMessage);
            if (response.ok) {
                resolve(response.result as Result);
            } else {
                reject(new Error(response.error.message));
            }
        };
        worker.addEventListener('message', onMessage);
        worker.postMessage(request);
    });

type ReducedActivationRequestInput = Extract<
    PrivatePreparationWorkerRequest,
    { operation: 'create-reduced-activation-package' }
>['input'];

const crashReducedActivationAtBoundary = async (
    runIdentity: string,
    participantPosition: number,
    workerUrl: URL,
    boundaryName: string,
    input: ReducedActivationRequestInput,
): Promise<void> => {
    const worker = new Worker(workerUrl, { type: 'module' });
    try {
        await rawRequest(worker, {
            requestId: 1,
            operation: 'initialize',
            input: {
                databaseName: databaseName(runIdentity, participantPosition),
                kernelUrl: kernelUrl.toString(),
                kernelOptions: { allowUnpinnedKernel: true },
                runtimeIdentity,
                candidateBuildIdentity,
            },
        });
        const boundary = new Promise<void>((resolve, reject) => {
            worker.addEventListener(
                'message',
                (event: MessageEvent<unknown>) => {
                    const data = event.data;
                    if (
                        typeof data === 'object' &&
                        data !== null &&
                        'testBoundary' in data &&
                        data.testBoundary === boundaryName
                    ) {
                        resolve();
                        return;
                    }
                    if (
                        typeof data === 'object' &&
                        data !== null &&
                        'requestId' in data &&
                        data.requestId === 2
                    ) {
                        const description =
                            'error' in data
                                ? JSON.stringify(data.error)
                                : 'the operation returned before its crash hook';
                        reject(
                            new Error(
                                `${boundaryName} was not reached: ${description}`,
                            ),
                        );
                    }
                },
            );
        });
        worker.postMessage({
            requestId: 2,
            operation: 'create-reduced-activation-package',
            input,
        } satisfies PrivatePreparationWorkerRequest);
        await boundary;
    } finally {
        worker.terminate();
    }
};

afterEach(async () => {
    for (const client of openClients) {
        client.close();
    }
    openClients.clear();
    for (const name of databaseNames) {
        await deleteDatabase(name);
    }
    databaseNames.clear();
});

describe('private preparation worker in Chromium', () => {
    it(
        'persists one exact package, opens only after durable consumption, and burns a crash-interrupted slot',
        { timeout: 300_000 },
        async () => {
            const runIdentity = crypto.randomUUID();
            const roster = await createCompletionRosterFixture();
            const canonicalRosterBytes = roster.canonicalRosterBytes;
            expect(roster.rosterIdentity).toHaveLength(64);
            const preparationPackages = await publishPreparationPackages(
                runIdentity,
                roster,
            );

            const firstSenderPosition = 2;
            const firstRecipientPosition = 8;
            const firstPackage = preparationPackages[firstSenderPosition];
            const firstCredential = roster.credentials[firstSenderPosition];
            const wrongCredential = roster.credentials[firstSenderPosition + 1];
            if (
                firstPackage === undefined ||
                firstCredential === undefined ||
                wrongCredential === undefined
            ) {
                throw new Error('The preparation fixture is incomplete.');
            }
            const firstSender = await openClient(
                runIdentity,
                firstSenderPosition,
            );
            await expect(
                firstSender.createPreparationPackage(
                    actionContext(firstSenderPosition),
                    canonicalRosterBytes,
                    wrongCredential.signingSecretKey,
                    wrongCredential.mailboxDecapsulationKey,
                    preparationAttempt,
                ),
            ).rejects.toThrow();
            const replayedPackage = await firstSender.createPreparationPackage(
                actionContext(firstSenderPosition),
                canonicalRosterBytes,
                firstCredential.signingSecretKey,
                firstCredential.mailboxDecapsulationKey,
                preparationAttempt,
            );
            expect(replayedPackage).toEqual(firstPackage);
            closeClient(firstSender);

            const firstRecipient = await openClient(
                runIdentity,
                firstRecipientPosition,
            );
            const firstPrivateBody =
                firstPackage.privateBodies[
                    remoteBodyIndex(firstSenderPosition, firstRecipientPosition)
                ];
            expect(firstPrivateBody).toBeInstanceOf(Uint8Array);
            if (firstPrivateBody === undefined) {
                throw new Error('The sender omitted the recipient body.');
            }
            await expect(
                firstRecipient.consumePrivatePreparation(
                    actionContext(firstRecipientPosition),
                    canonicalRosterBytes,
                    preparationAttempt,
                    firstPackage.parentBody,
                    firstPackage.parentSignature,
                    firstPrivateBody,
                ),
            ).resolves.toEqual({
                senderPosition: firstSenderPosition,
                status: 'resolved',
            });
            await expect(
                firstRecipient.consumePrivatePreparation(
                    actionContext(firstRecipientPosition),
                    canonicalRosterBytes,
                    preparationAttempt,
                    firstPackage.parentBody,
                    firstPackage.parentSignature,
                    firstPrivateBody,
                ),
            ).resolves.toEqual({
                senderPosition: firstSenderPosition,
                status: 'already-resolved',
            });
            const mutatedBody = Uint8Array.from(firstPrivateBody);
            mutatedBody[mutatedBody.byteLength - 1] ^= 1;
            await expect(
                firstRecipient.consumePrivatePreparation(
                    actionContext(firstRecipientPosition),
                    canonicalRosterBytes,
                    preparationAttempt,
                    firstPackage.parentBody,
                    firstPackage.parentSignature,
                    mutatedBody,
                ),
            ).rejects.toThrow();
            closeClient(firstRecipient);

            const restoredRecipient = await openClient(
                runIdentity,
                firstRecipientPosition,
            );
            await expect(
                restoredRecipient.consumePrivatePreparation(
                    actionContext(firstRecipientPosition),
                    canonicalRosterBytes,
                    preparationAttempt,
                    firstPackage.parentBody,
                    firstPackage.parentSignature,
                    firstPrivateBody,
                ),
            ).resolves.toEqual({
                senderPosition: firstSenderPosition,
                status: 'already-resolved',
            });
            closeClient(restoredRecipient);

            const crashSenderPosition = 3;
            const crashRecipientPosition = 9;
            const crashPackage = preparationPackages[crashSenderPosition];
            if (crashPackage === undefined) {
                throw new Error('The crash preparation fixture is incomplete.');
            }
            const crashPrivateBody =
                crashPackage.privateBodies[
                    remoteBodyIndex(crashSenderPosition, crashRecipientPosition)
                ];
            if (crashPrivateBody === undefined) {
                throw new Error('The crash sender omitted the recipient body.');
            }

            const crashWorker = new Worker(crashWorkerUrl, { type: 'module' });
            await rawRequest(crashWorker, {
                requestId: 1,
                operation: 'initialize',
                input: {
                    databaseName: databaseName(
                        runIdentity,
                        crashRecipientPosition,
                    ),
                    kernelUrl: kernelUrl.toString(),
                    kernelOptions: { allowUnpinnedKernel: true },
                    runtimeIdentity,
                    candidateBuildIdentity,
                },
            });
            const durableBoundary = new Promise<void>((resolve) => {
                crashWorker.addEventListener(
                    'message',
                    (event: MessageEvent<unknown>) => {
                        const data = event.data;
                        if (
                            typeof data === 'object' &&
                            data !== null &&
                            'testBoundary' in data &&
                            data.testBoundary === 'durably-consumed'
                        ) {
                            resolve();
                        }
                    },
                );
            });
            crashWorker.postMessage({
                requestId: 2,
                operation: 'consume-private-preparation',
                input: {
                    ...actionContext(crashRecipientPosition),
                    canonicalRosterBytes,
                    preparationAttempt,
                    parentBody: crashPackage.parentBody,
                    parentSignature: crashPackage.parentSignature,
                    privateBody: crashPrivateBody,
                },
            } satisfies PrivatePreparationWorkerRequest);
            await durableBoundary;
            crashWorker.terminate();

            const recoveredRecipient = await openClient(
                runIdentity,
                crashRecipientPosition,
            );
            await expect(
                recoveredRecipient.consumePrivatePreparation(
                    actionContext(crashRecipientPosition),
                    canonicalRosterBytes,
                    preparationAttempt,
                    crashPackage.parentBody,
                    crashPackage.parentSignature,
                    crashPrivateBody,
                ),
            ).resolves.toEqual({
                senderPosition: crashSenderPosition,
                status: 'burned',
            });
            closeClient(recoveredRecipient);
        },
    );

    it(
        'executes and restores complete preparation, source, and finality',
        { timeout: 600_000 },
        async () => {
            const runIdentity = crypto.randomUUID();
            const submittedScores = Uint8Array.of(
                1,
                10,
                3,
                9,
                5,
                8,
                7,
                6,
                4,
                2,
            );
            const roster = await createCompletionRosterFixture();
            const canonicalRosterBytes = roster.canonicalRosterBytes;
            const preparationPackages = await publishPreparationPackages(
                runIdentity,
                roster,
            );
            const preparationParents = preparationPackages.map((entry) => ({
                body: entry.parentBody,
                signature: entry.parentSignature,
            }));

            for (
                let recipientPosition = 0;
                recipientPosition < participantCount;
                recipientPosition += 1
            ) {
                const client = await openClient(runIdentity, recipientPosition);
                for (
                    let senderPosition = 0;
                    senderPosition < participantCount;
                    senderPosition += 1
                ) {
                    if (senderPosition === recipientPosition) {
                        continue;
                    }
                    const senderPackage = preparationPackages[senderPosition];
                    const privateBody =
                        senderPackage?.privateBodies[
                            remoteBodyIndex(senderPosition, recipientPosition)
                        ];
                    if (
                        senderPackage === undefined ||
                        privateBody === undefined
                    ) {
                        throw new Error(
                            'The complete preparation fixture is incomplete.',
                        );
                    }
                    await expect(
                        client.consumePrivatePreparation(
                            actionContext(recipientPosition),
                            canonicalRosterBytes,
                            preparationAttempt,
                            senderPackage.parentBody,
                            senderPackage.parentSignature,
                            privateBody,
                        ),
                    ).resolves.toEqual({
                        senderPosition,
                        status: 'resolved',
                    });
                }
                closeClient(client);
            }

            const sourcePosition = 0;
            const crashWorker = new Worker(sourceCrashWorkerUrl, {
                type: 'module',
            });
            await rawRequest(crashWorker, {
                requestId: 1,
                operation: 'initialize',
                input: {
                    databaseName: databaseName(runIdentity, sourcePosition),
                    kernelUrl: kernelUrl.toString(),
                    kernelOptions: { allowUnpinnedKernel: true },
                    runtimeIdentity,
                    candidateBuildIdentity,
                },
            });
            const sourceBoundary = new Promise<void>((resolve) => {
                crashWorker.addEventListener(
                    'message',
                    (event: MessageEvent<unknown>) => {
                        const data = event.data;
                        if (
                            typeof data === 'object' &&
                            data !== null &&
                            'testBoundary' in data &&
                            data.testBoundary === 'source-durably-bound'
                        ) {
                            resolve();
                        }
                    },
                );
            });
            crashWorker.postMessage({
                requestId: 2,
                operation: 'create-source-package',
                input: {
                    ...actionContext(sourcePosition),
                    canonicalRosterBytes,
                    preparationAttempt,
                    preparationParents,
                    choice: {
                        declaration: 'submit',
                        scoreEncodings: submittedScores,
                    },
                },
            } satisfies PrivatePreparationWorkerRequest);
            await sourceBoundary;
            crashWorker.terminate();

            const recoveredSource = await openClient(
                runIdentity,
                sourcePosition,
            );
            const submitted = await recoveredSource.createSourcePackage(
                actionContext(sourcePosition),
                canonicalRosterBytes,
                preparationAttempt,
                preparationParents,
                {
                    declaration: 'submit',
                    scoreEncodings: submittedScores,
                },
            );
            expect(submitted.sourceBody).toHaveLength(
                submittedSourceBodyByteLength,
            );
            await expect(
                recoveredSource.createSourcePackage(
                    actionContext(sourcePosition),
                    canonicalRosterBytes,
                    preparationAttempt,
                    preparationParents,
                    {
                        declaration: 'submit',
                        scoreEncodings: submittedScores,
                    },
                ),
            ).resolves.toEqual(submitted);
            await expect(
                recoveredSource.createSourcePackage(
                    actionContext(sourcePosition),
                    canonicalRosterBytes,
                    preparationAttempt,
                    preparationParents,
                    {
                        declaration: 'submit',
                        scoreEncodings: new Uint8Array(10),
                    },
                ),
            ).rejects.toThrow();
            closeClient(recoveredSource);

            const restoredSource = await openClient(
                runIdentity,
                sourcePosition,
            );
            await expect(
                restoredSource.createSourcePackage(
                    actionContext(sourcePosition),
                    canonicalRosterBytes,
                    preparationAttempt,
                    preparationParents,
                    {
                        declaration: 'submit',
                        scoreEncodings: submittedScores,
                    },
                ),
            ).resolves.toEqual(submitted);
            closeClient(restoredSource);

            const abstainingPosition = 1;
            const abstainingSource = await openClient(
                runIdentity,
                abstainingPosition,
            );
            const abstention = await abstainingSource.createSourcePackage(
                actionContext(abstainingPosition),
                canonicalRosterBytes,
                preparationAttempt,
                preparationParents,
                { declaration: 'abstain' },
            );
            expect(abstention.sourceBody).toHaveLength(
                abstentionSourceBodyByteLength,
            );
            closeClient(abstainingSource);

            const malformedPosition = 2;
            const malformedSource = await openClient(
                runIdentity,
                malformedPosition,
            );
            const mutatedParents = preparationParents.map((parent) => ({
                body: Uint8Array.from(parent.body),
                signature: Uint8Array.from(parent.signature),
            }));
            const mutatedParent = mutatedParents[3];
            if (mutatedParent === undefined) {
                throw new Error('The mutation fixture omitted a parent.');
            }
            mutatedParent.body[mutatedParent.body.byteLength - 1] ^= 1;
            await expect(
                malformedSource.createSourcePackage(
                    actionContext(malformedPosition),
                    canonicalRosterBytes,
                    preparationAttempt,
                    mutatedParents,
                    { declaration: 'abstain' },
                ),
            ).rejects.toThrow();
            await expect(
                malformedSource.createSourcePackage(
                    actionContext(malformedPosition),
                    canonicalRosterBytes,
                    preparationAttempt + 1,
                    preparationParents,
                    { declaration: 'abstain' },
                ),
            ).rejects.toThrow();
            const recoveredAbstention =
                await malformedSource.createSourcePackage(
                    actionContext(malformedPosition),
                    canonicalRosterBytes,
                    preparationAttempt,
                    preparationParents,
                    { declaration: 'abstain' },
                );
            expect(recoveredAbstention.sourceBody).toHaveLength(
                abstentionSourceBodyByteLength,
            );
            expect(recoveredAbstention.sourceSignature).toHaveLength(
                actionSignatureCarrierByteLength,
            );
            closeClient(malformedSource);

            const sourcePackages: (PublishedSourcePackage | undefined)[] =
                Array.from({ length: participantCount });
            const sourceDeclarations = Array.from(
                { length: participantCount },
                () => 'abstain' as const,
            ) as ('abstain' | 'submit')[];
            sourcePackages[0] = submitted;
            sourceDeclarations[0] = 'submit';
            sourcePackages[1] = abstention;
            sourcePackages[2] = recoveredAbstention;
            const unusableScores = [
                new Uint8Array(10),
                new Uint8Array(10).fill(15),
            ];
            for (
                let participantPosition = 3;
                participantPosition < participantCount;
                participantPosition += 1
            ) {
                const client = await openClient(
                    runIdentity,
                    participantPosition,
                );
                const unusable = unusableScores[participantPosition - 3];
                const choice =
                    unusable === undefined
                        ? ({ declaration: 'abstain' } as const)
                        : ({
                              declaration: 'submit',
                              scoreEncodings: unusable,
                          } as const);
                sourceDeclarations[participantPosition] = choice.declaration;
                sourcePackages[participantPosition] =
                    await client.createSourcePackage(
                        actionContext(participantPosition),
                        canonicalRosterBytes,
                        preparationAttempt,
                        preparationParents,
                        choice,
                    );
                closeClient(client);
            }
            const sourceCarriers = sourcePackages.map((source, position) => {
                if (source === undefined) {
                    throw new Error(
                        'The finalized source roster is incomplete.',
                    );
                }
                return {
                    declaration: sourceDeclarations[position] ?? 'abstain',
                    body: source.sourceBody,
                    signature: source.sourceSignature,
                };
            });

            const topCount = 1;
            const finalityPackages: PublishedFinalityPackage[] = [];
            for (
                let participantPosition = 0;
                participantPosition < participantCount;
                participantPosition += 1
            ) {
                const client = await openClient(
                    runIdentity,
                    participantPosition,
                );
                const finality = await client.createFinalitySignature(
                    actionContext(participantPosition),
                    canonicalRosterBytes,
                    preparationAttempt,
                    sourceCarriers,
                    topCount,
                );
                finalityPackages.push(finality);
                closeClient(client);
            }
            const finalityTargetIdentity = finalityPackages[0]?.targetIdentity;
            if (finalityTargetIdentity === undefined) {
                throw new Error('The finality roster is empty.');
            }
            expect(
                finalityPackages.every(
                    (entry) =>
                        entry.targetKind === 'computation' &&
                        entry.topCount === topCount &&
                        entry.sourceSubmissionBitmap === 0b0000_0001_1001 &&
                        entry.targetIdentity.every(
                            (byte, index) =>
                                byte === finalityTargetIdentity[index],
                        ),
                ),
            ).toBe(true);
            const conflictingFinality = await openClient(runIdentity, 9);
            await expect(
                conflictingFinality.createFinalitySignature(
                    actionContext(9),
                    canonicalRosterBytes,
                    preparationAttempt,
                    [...sourceCarriers].reverse(),
                    topCount,
                ),
            ).rejects.toThrow();
            await expect(
                conflictingFinality.createFinalitySignature(
                    actionContext(9),
                    canonicalRosterBytes,
                    preparationAttempt,
                    sourceCarriers,
                    topCount + 1,
                ),
            ).rejects.toThrow();
            await expect(
                conflictingFinality.createFinalitySignature(
                    {
                        ...actionContext(9),
                        actionDefinitionIdentity: new Uint8Array(64).fill(0xee),
                    },
                    canonicalRosterBytes,
                    preparationAttempt,
                    sourceCarriers,
                    topCount,
                ),
            ).rejects.toThrow();
            closeClient(conflictingFinality);

            const activationPosition = 0;
            const finalitySignatures = finalityPackages
                .slice(0, 8)
                .map((finality, signerPosition) => ({
                    signerPosition,
                    signature: finality.finalitySignature,
                }));
            const initialWireValues = Uint8Array.of(1, 2, 3, 4);
            const gateMaskShares = Uint8Array.from(
                { length: 14 },
                (_, index) => index % 16,
            );
            const terminalMaskShares = Uint8Array.of(5, 6, 7);
            const activationInput: ReducedActivationRequestInput = {
                ...actionContext(activationPosition),
                canonicalRosterBytes,
                preparationAttempt,
                preparationParents,
                sources: sourceCarriers,
                finalitySignatures,
                topCount,
                initialWireValues,
                gateMaskShares,
                terminalMaskShares,
            };
            await crashReducedActivationAtBoundary(
                runIdentity,
                activationPosition,
                activationAllocationCrashWorkerUrl,
                'activation-durably-allocated',
                activationInput,
            );
            await crashReducedActivationAtBoundary(
                runIdentity,
                activationPosition,
                activationBodyCrashWorkerUrl,
                'activation-body-durably-bound',
                activationInput,
            );
            const retainedUnsignedBody = await readRawActivationRecord(
                databaseName(runIdentity, activationPosition),
                activationIdentifier(activationPosition),
            );
            if (retainedUnsignedBody === undefined) {
                throw new Error(
                    'The body crash boundary omitted retained activation state.',
                );
            }
            await crashReducedActivationAtBoundary(
                runIdentity,
                activationPosition,
                activationPublicationCrashWorkerUrl,
                'activation-durably-published',
                activationInput,
            );

            const activationClient = await openClient(
                runIdentity,
                activationPosition,
            );
            const activation: PublishedReducedActivationPackage =
                await activationClient.createReducedActivationPackage(
                    actionContext(activationPosition),
                    canonicalRosterBytes,
                    preparationAttempt,
                    preparationParents,
                    sourceCarriers,
                    finalitySignatures,
                    topCount,
                    initialWireValues,
                    gateMaskShares,
                    terminalMaskShares,
                );
            expect(activation.chunk).toHaveLength(69_099);
            expect(activation.chunkIdentity).toHaveLength(64);
            expect(activation.manifest).toHaveLength(254);
            expect(activation.manifestIdentity).toHaveLength(64);
            expect(activation.activationSignature).toHaveLength(
                actionSignatureCarrierByteLength,
            );
            await expect(
                activationClient.createReducedActivationPackage(
                    actionContext(activationPosition),
                    canonicalRosterBytes,
                    preparationAttempt,
                    preparationParents,
                    sourceCarriers,
                    finalitySignatures,
                    topCount,
                    initialWireValues,
                    gateMaskShares,
                    terminalMaskShares,
                ),
            ).resolves.toEqual(activation);

            const alternatePreparationParents = preparationParents.map(
                (parent) => ({
                    body: Uint8Array.from(parent.body),
                    signature: Uint8Array.from(parent.signature),
                }),
            );
            const alternatePreparationParent = alternatePreparationParents[4];
            if (alternatePreparationParent === undefined) {
                throw new Error('The activation preparation fixture is empty.');
            }
            alternatePreparationParent.body[
                alternatePreparationParent.body.byteLength - 1
            ] ^= 1;
            await expect(
                activationClient.createReducedActivationPackage(
                    actionContext(activationPosition),
                    canonicalRosterBytes,
                    preparationAttempt,
                    alternatePreparationParents,
                    sourceCarriers,
                    finalitySignatures,
                    topCount,
                    initialWireValues,
                    gateMaskShares,
                    terminalMaskShares,
                ),
            ).rejects.toThrow();

            const alternateGateMaskShares = Uint8Array.from(gateMaskShares);
            alternateGateMaskShares[0] =
                ((alternateGateMaskShares[0] ?? 0) + 1) % 16;
            await expect(
                activationClient.createReducedActivationPackage(
                    actionContext(activationPosition),
                    canonicalRosterBytes,
                    preparationAttempt,
                    preparationParents,
                    sourceCarriers,
                    finalitySignatures,
                    topCount,
                    initialWireValues,
                    alternateGateMaskShares,
                    terminalMaskShares,
                ),
            ).rejects.toMatchObject({ name: 'Conflict' });
            await expect(
                activationClient.createReducedActivationPackage(
                    actionContext(activationPosition),
                    canonicalRosterBytes,
                    preparationAttempt,
                    preparationParents,
                    sourceCarriers,
                    finalitySignatures.slice(0, 7),
                    topCount,
                    initialWireValues,
                    gateMaskShares,
                    terminalMaskShares,
                ),
            ).rejects.toThrow();
            const corruptFinalitySignatures = finalitySignatures.map(
                (entry) => ({
                    signerPosition: entry.signerPosition,
                    signature: Uint8Array.from(entry.signature),
                }),
            );
            const corruptSignature = corruptFinalitySignatures[3];
            if (corruptSignature === undefined) {
                throw new Error('The finality corruption fixture is empty.');
            }
            corruptSignature.signature[
                corruptSignature.signature.byteLength - 1
            ] ^= 1;
            await expect(
                activationClient.createReducedActivationPackage(
                    actionContext(activationPosition),
                    canonicalRosterBytes,
                    preparationAttempt,
                    preparationParents,
                    sourceCarriers,
                    corruptFinalitySignatures,
                    topCount,
                    initialWireValues,
                    gateMaskShares,
                    terminalMaskShares,
                ),
            ).rejects.toThrow();
            closeClient(activationClient);

            const restoredActivationClient = await openClient(
                runIdentity,
                activationPosition,
            );
            await expect(
                restoredActivationClient.createReducedActivationPackage(
                    actionContext(activationPosition),
                    canonicalRosterBytes,
                    preparationAttempt,
                    preparationParents,
                    sourceCarriers,
                    finalitySignatures,
                    topCount,
                    initialWireValues,
                    gateMaskShares,
                    terminalMaskShares,
                ),
            ).resolves.toEqual(activation);
            closeClient(restoredActivationClient);

            await restoreRawActivationRecord(
                databaseName(runIdentity, activationPosition),
                retainedUnsignedBody,
            );
            const rollbackClient = await openClient(
                runIdentity,
                activationPosition,
            );
            await expect(
                rollbackClient.createReducedActivationPackage(
                    actionContext(activationPosition),
                    canonicalRosterBytes,
                    preparationAttempt,
                    preparationParents,
                    sourceCarriers,
                    finalitySignatures,
                    topCount,
                    initialWireValues,
                    gateMaskShares,
                    terminalMaskShares,
                ),
            ).rejects.toMatchObject({ name: 'StateLost' });
            closeClient(rollbackClient);

            await deleteRawActivationRecord(
                databaseName(runIdentity, activationPosition),
                activationIdentifier(activationPosition),
            );
            const stateLossClient = await openClient(
                runIdentity,
                activationPosition,
            );
            await expect(
                stateLossClient.createReducedActivationPackage(
                    actionContext(activationPosition),
                    canonicalRosterBytes,
                    preparationAttempt,
                    preparationParents,
                    sourceCarriers,
                    finalitySignatures,
                    topCount,
                    initialWireValues,
                    gateMaskShares,
                    terminalMaskShares,
                ),
            ).rejects.toMatchObject({ name: 'StateLost' });
            closeClient(stateLossClient);

            const computationResultClient = await openClient(runIdentity, 0);
            await expect(
                computationResultClient.readTallyResult(actionContext(0)),
            ).rejects.toThrow();
            closeClient(computationResultClient);
        },
    );

    it(
        'finalizes an all-abstain roster without an activation wave',
        { timeout: 300_000 },
        async () => {
            const runIdentity = crypto.randomUUID();
            const { canonicalRosterBytes, preparationParents } =
                await createCompletePreparation(runIdentity);
            const sources: PublishedSourcePackage[] = [];
            for (
                let participantPosition = 0;
                participantPosition < participantCount;
                participantPosition += 1
            ) {
                const client = await openClient(
                    runIdentity,
                    participantPosition,
                );
                sources.push(
                    await client.createSourcePackage(
                        actionContext(participantPosition),
                        canonicalRosterBytes,
                        preparationAttempt,
                        preparationParents,
                        { declaration: 'abstain' },
                    ),
                );
                closeClient(client);
            }
            const sourceCarriers = sources.map((source) => ({
                declaration: 'abstain' as const,
                body: source.sourceBody,
                signature: source.sourceSignature,
            }));
            const topCount = 10;
            const finalities: PublishedFinalityPackage[] = [];
            for (
                let participantPosition = 0;
                participantPosition < participantCount;
                participantPosition += 1
            ) {
                const client = await openClient(
                    runIdentity,
                    participantPosition,
                );
                finalities.push(
                    await client.createFinalitySignature(
                        actionContext(participantPosition),
                        canonicalRosterBytes,
                        preparationAttempt,
                        sourceCarriers,
                        topCount,
                    ),
                );
                closeClient(client);
            }
            expect(
                finalities.every(
                    (finality) =>
                        finality.targetKind === 'no-result' &&
                        finality.topCount === topCount &&
                        finality.sourceSubmissionBitmap === 0,
                ),
            ).toBe(true);
            const certificate = finalities
                .slice(0, 8)
                .map((finality, signerPosition) => ({
                    signerPosition,
                    signature: finality.finalitySignature,
                }));
            const resultClient = await openClient(runIdentity, 0);
            await expect(
                resultClient.readTallyResult(actionContext(0)),
            ).rejects.toThrow();
            await expect(
                resultClient.finalizeNoResult(
                    actionContext(0),
                    canonicalRosterBytes,
                    preparationAttempt,
                    sourceCarriers,
                    certificate.slice(0, 7),
                    topCount,
                ),
            ).rejects.toThrow();
            await expect(
                resultClient.finalizeNoResult(
                    actionContext(0),
                    canonicalRosterBytes,
                    preparationAttempt,
                    sourceCarriers,
                    certificate,
                    topCount,
                ),
            ).resolves.toMatchObject({
                kind: 'no-result',
                acceptedBallotAuthorshipBitmap: 0,
            });
            closeClient(resultClient);
            const restoredResultClient = await openClient(runIdentity, 0);
            await expect(
                restoredResultClient.readTallyResult(actionContext(0)),
            ).resolves.toMatchObject({
                kind: 'no-result',
                acceptedBallotAuthorshipBitmap: 0,
            });
            closeClient(restoredResultClient);
        },
    );
});

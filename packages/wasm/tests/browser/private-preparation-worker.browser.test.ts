import { afterEach, describe, expect, it } from 'vitest';

import { PrivatePreparationWorkerClient } from '../../src/private-preparation-worker-client.js';
import type {
    PrivatePreparationActionContext,
    PrivatePreparationWorkerRequest,
    PrivatePreparationWorkerResponse,
    PublishedFinalityPackage,
    PublishedPreparationPackage,
    PublishedSourcePackage,
} from '../../src/private-preparation-worker-protocol.js';
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
        actionKeySetBodies: readonly Uint8Array[];
        preparationPackages: readonly PublishedPreparationPackage[];
        preparationParents: readonly Readonly<{
            body: Uint8Array;
            signature: Uint8Array;
        }>[];
    }>
> => {
    const actionKeySetBodies: Uint8Array[] = [];
    for (
        let participantPosition = 0;
        participantPosition < participantCount;
        participantPosition += 1
    ) {
        const client = await openClient(runIdentity, participantPosition);
        const registration = await client.registerActionKeys(
            actionContext(participantPosition),
        );
        actionKeySetBodies.push(registration.actionKeySetBody);
        closeClient(client);
    }
    for (
        let participantPosition = 0;
        participantPosition < participantCount;
        participantPosition += 1
    ) {
        const client = await openClient(runIdentity, participantPosition);
        await client.confirmActionKeyRoster(
            actionContext(participantPosition),
            actionKeySetBodies,
        );
        closeClient(client);
    }
    const preparationPackages: PublishedPreparationPackage[] = [];
    for (
        let participantPosition = 0;
        participantPosition < participantCount;
        participantPosition += 1
    ) {
        const client = await openClient(runIdentity, participantPosition);
        preparationPackages.push(
            await client.createPreparationPackage(
                actionContext(participantPosition),
                actionKeySetBodies,
                preparationAttempt,
            ),
        );
        closeClient(client);
    }
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
                actionKeySetBodies,
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
        actionKeySetBodies,
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
            const actionKeySetBodies: Uint8Array[] = [];
            for (
                let participantPosition = 0;
                participantPosition < participantCount;
                participantPosition += 1
            ) {
                const client = await openClient(
                    runIdentity,
                    participantPosition,
                );
                const registration = await client.registerActionKeys(
                    actionContext(participantPosition),
                );
                actionKeySetBodies.push(registration.actionKeySetBody);
                closeClient(client);
            }

            let expectedRosterIdentity: Uint8Array | undefined;
            for (
                let participantPosition = 0;
                participantPosition < participantCount;
                participantPosition += 1
            ) {
                const client = await openClient(
                    runIdentity,
                    participantPosition,
                );
                const confirmation = await client.confirmActionKeyRoster(
                    actionContext(participantPosition),
                    actionKeySetBodies,
                );
                expectedRosterIdentity ??=
                    confirmation.actionKeySetRosterIdentity;
                expect(confirmation.actionKeySetRosterIdentity).toEqual(
                    expectedRosterIdentity,
                );
                closeClient(client);
            }

            const firstSenderPosition = 2;
            const firstRecipientPosition = 8;
            const firstSender = await openClient(
                runIdentity,
                firstSenderPosition,
            );
            const firstPackage = await firstSender.createPreparationPackage(
                actionContext(firstSenderPosition),
                actionKeySetBodies,
                preparationAttempt,
            );
            const replayedPackage = await firstSender.createPreparationPackage(
                actionContext(firstSenderPosition),
                actionKeySetBodies,
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
                    actionKeySetBodies,
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
                    actionKeySetBodies,
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
                    actionKeySetBodies,
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
                    actionKeySetBodies,
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
            const crashSender = await openClient(
                runIdentity,
                crashSenderPosition,
            );
            const crashPackage = await crashSender.createPreparationPackage(
                actionContext(crashSenderPosition),
                actionKeySetBodies,
                preparationAttempt,
            );
            closeClient(crashSender);
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
                    actionKeySetBodies,
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
                    actionKeySetBodies,
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
            const actionKeySetBodies: Uint8Array[] = [];
            for (
                let participantPosition = 0;
                participantPosition < participantCount;
                participantPosition += 1
            ) {
                const client = await openClient(
                    runIdentity,
                    participantPosition,
                );
                const registration = await client.registerActionKeys(
                    actionContext(participantPosition),
                );
                actionKeySetBodies.push(registration.actionKeySetBody);
                closeClient(client);
            }
            for (
                let participantPosition = 0;
                participantPosition < participantCount;
                participantPosition += 1
            ) {
                const client = await openClient(
                    runIdentity,
                    participantPosition,
                );
                await client.confirmActionKeyRoster(
                    actionContext(participantPosition),
                    actionKeySetBodies,
                );
                closeClient(client);
            }

            const preparationPackages: PublishedPreparationPackage[] = [];
            for (
                let participantPosition = 0;
                participantPosition < participantCount;
                participantPosition += 1
            ) {
                const client = await openClient(
                    runIdentity,
                    participantPosition,
                );
                preparationPackages.push(
                    await client.createPreparationPackage(
                        actionContext(participantPosition),
                        actionKeySetBodies,
                        preparationAttempt,
                    ),
                );
                closeClient(client);
            }
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
                            actionKeySetBodies,
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
                    actionKeySetBodies,
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
                actionKeySetBodies,
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
                    actionKeySetBodies,
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
                    actionKeySetBodies,
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
                    actionKeySetBodies,
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
                actionKeySetBodies,
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
                    actionKeySetBodies,
                    preparationAttempt,
                    mutatedParents,
                    { declaration: 'abstain' },
                ),
            ).rejects.toThrow();
            await expect(
                malformedSource.createSourcePackage(
                    actionContext(malformedPosition),
                    actionKeySetBodies,
                    preparationAttempt + 1,
                    preparationParents,
                    { declaration: 'abstain' },
                ),
            ).rejects.toThrow();
            const recoveredAbstention =
                await malformedSource.createSourcePackage(
                    actionContext(malformedPosition),
                    actionKeySetBodies,
                    preparationAttempt,
                    preparationParents,
                    { declaration: 'abstain' },
                );
            expect(recoveredAbstention.sourceBody).toHaveLength(
                abstentionSourceBodyByteLength,
            );
            expect(recoveredAbstention.sourceSignature).toHaveLength(6_388);
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
                        actionKeySetBodies,
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
                    actionKeySetBodies,
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
                    actionKeySetBodies,
                    preparationAttempt,
                    [...sourceCarriers].reverse(),
                    topCount,
                ),
            ).rejects.toThrow();
            await expect(
                conflictingFinality.createFinalitySignature(
                    actionContext(9),
                    actionKeySetBodies,
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
                    actionKeySetBodies,
                    preparationAttempt,
                    sourceCarriers,
                    topCount,
                ),
            ).rejects.toThrow();
            closeClient(conflictingFinality);

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
            const { actionKeySetBodies, preparationParents } =
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
                        actionKeySetBodies,
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
                        actionKeySetBodies,
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
                    actionKeySetBodies,
                    preparationAttempt,
                    sourceCarriers,
                    certificate.slice(0, 7),
                    topCount,
                ),
            ).rejects.toThrow();
            await expect(
                resultClient.finalizeNoResult(
                    actionContext(0),
                    actionKeySetBodies,
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

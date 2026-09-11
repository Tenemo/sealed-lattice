import { createFoundationRosterFixture } from '../foundation-roster-fixture.js';

import * as sdk from 'sealed-lattice';

const run = async (participantCount: number, optionCount: number) => {
    const manifest = await sdk.createCanonicalManifest({
        question: 'Choose priorities',
        options: Array.from(
            { length: optionCount },
            (_, index) => `Option ${String(index + 1)}`,
        ),
    });
    const definition = await sdk.createCanonicalActionDefinition({
        submissionCutoffUnixMilliseconds: 1_800_000_000_000n,
        topCount: optionCount,
    });
    const policy = await sdk.createCanonicalBoardPolicy({
        boardOriginIdentifier: 'board.example',
    });
    const ceremonyInput = {
        canonicalManifestBytes: manifest.canonicalBytes,
        canonicalRosterBytes: createFoundationRosterFixture(participantCount),
        ceremonyIdentifier: 'foundation-browser-test',
        expectedSuiteId: '11'.repeat(64),
    };
    const ceremony = await sdk.verifyCanonicalCeremonyContext(ceremonyInput);
    if (!ceremony.isValid)
        throw new Error(`Valid roster was refused: ${ceremony.refusalReason}`);
    const actionInput = {
        ...ceremonyInput,
        actionIdentifier: 'scored-poll',
        canonicalActionDefinitionBytes: definition.canonicalBytes,
        canonicalBoardPolicyBytes: policy.canonicalBytes,
        expectedCeremonyContextHash: ceremony.value.ceremonyContextHash,
    };
    const action = await sdk.verifyCanonicalActionContext(actionInput);
    const otherManifest = await sdk.createCanonicalManifest({
        question: 'Different poll',
        options: Array.from(
            { length: optionCount },
            (_, index) => `Option ${String(index + 1)}`,
        ),
    });
    const replay = await sdk.verifyCanonicalActionContext({
        ...actionInput,
        canonicalManifestBytes: otherManifest.canonicalBytes,
    });
    const wrongSuite = await sdk.verifyCanonicalActionContext({
        ...actionInput,
        expectedSuiteId: '22'.repeat(64),
    });
    const duplicateRoster = createFoundationRosterFixture(participantCount);
    // Each canonical entry has its own position; duplicate only the key material.
    const entryLength = 8 + 3 * 6 + 2 + 1952 + 1184;
    const keyOffset = 8 + 6 + 6 + 8 + 6 + 2 + 6;
    duplicateRoster.set(
        duplicateRoster.slice(keyOffset, keyOffset + 1952),
        keyOffset + entryLength,
    );
    const duplicate = await sdk.verifyCanonicalCeremonyContext({
        ...ceremonyInput,
        canonicalRosterBytes: duplicateRoster,
    });
    const truncated = await sdk.verifyCanonicalManifest(
        manifest.canonicalBytes.slice(0, -1),
    );
    const afterInvalid = await sdk.verifyCanonicalActionContext(actionInput);
    const oversizedResult = await sdk.createCanonicalActionDefinition({
        submissionCutoffUnixMilliseconds: 1_800_000_000_000n,
        topCount: 20,
    });
    return {
        manifest: await sdk.verifyCanonicalManifest(manifest.canonicalBytes),
        definition: await sdk.verifyCanonicalActionDefinition(
            definition.canonicalBytes,
        ),
        policy: await sdk.verifyCanonicalBoardPolicy(policy.canonicalBytes),
        ceremony,
        action,
        replay,
        wrongSuite,
        duplicate,
        truncated,
        afterInvalid,
        oversizedResult: await sdk.verifyCanonicalActionContext({
            ...actionInput,
            canonicalActionDefinitionBytes: oversizedResult.canonicalBytes,
        }),
    };
};

export type FoundationWorkerResult = Awaited<ReturnType<typeof run>>;
export type KernelFixture = 'valid' | 'tampered' | 'oversized';

self.onmessage = (
    event: MessageEvent<{
        participantCount: number;
        optionCount: number;
        kernelFixture: KernelFixture;
    }>,
) => {
    void (async () => {
        let downloadCancelled = false;
        try {
            if (event.data.kernelFixture === 'oversized') {
                globalThis.fetch = () =>
                    Promise.resolve(
                        new Response(
                            new ReadableStream<Uint8Array>({
                                start(controller) {
                                    controller.enqueue(
                                        new Uint8Array(8_388_608),
                                    );
                                    controller.enqueue(new Uint8Array(1));
                                    // Deliberately remain open: refusal must not wait for EOF.
                                },
                                cancel() {
                                    downloadCancelled = true;
                                },
                            }),
                            { headers: { 'Content-Length': '1' } },
                        ),
                    );
            } else if (event.data.kernelFixture === 'tampered') {
                const fetchOriginal = globalThis.fetch.bind(globalThis);
                globalThis.fetch = async (...arguments_) => {
                    const response = await fetchOriginal(...arguments_);
                    const bytes = new Uint8Array(await response.arrayBuffer());
                    bytes[0] ^= 1;
                    return new Response(bytes, {
                        status: response.status,
                        headers: response.headers,
                    });
                };
            }
            const result = await run(
                event.data.participantCount,
                event.data.optionCount,
            );
            self.postMessage({ result });
        } catch (error) {
            self.postMessage({
                error: error instanceof Error ? error.message : String(error),
                downloadCancelled,
            });
        }
    })();
};

import { foundationProfile, type ProtocolHash } from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import { openFoundationCeremonyRuntime } from '#packages/wasm/src/index';
import type { PublishedSdkKernel } from '#packages/wasm/src/transcript-core-bridge/kernel-contracts';

const zeroHash = '00'.repeat(64);
const refused = Object.freeze({
    isValid: false as const,
    refusalReason: 'malformedEncoding' as const,
});

const openRuntimeWithMethods = (methods: Readonly<Record<string, unknown>>) =>
    openFoundationCeremonyRuntime(methods as unknown as PublishedSdkKernel);

const manifestInput = () => ({
    displayTitle: 'Foundation vote',
    optionDefinitions: Array.from(
        { length: foundationProfile.optionCount },
        (_unused, optionIndex) => ({
            displayLabel: `Option ${String(optionIndex)}`,
            optionIdentifier: `option-${String(optionIndex)}`,
            optionIndex,
        }),
    ),
});

const detachBytes = (): Uint8Array => {
    const bytes = new Uint8Array([0x31]);
    structuredClone(bytes.buffer, { transfer: [bytes.buffer] });
    return bytes;
};

describe('foundation ceremony hostile JavaScript ingress', () => {
    it('refuses accessor fields without invoking them', () => {
        const runtime = openRuntimeWithMethods({});
        let accessorReadCount = 0;

        const manifest = manifestInput();
        Object.defineProperty(manifest, 'displayTitle', {
            enumerable: true,
            get: () => {
                accessorReadCount += 1;
                return 'mutated';
            },
        });
        expect(() => runtime.encodeManifest(manifest)).toThrow(TypeError);

        const actionDefinition = { topCount: 7 } as {
            submissionCutoffUnixMilliseconds: bigint;
            topCount: number;
        };
        Object.defineProperty(
            actionDefinition,
            'submissionCutoffUnixMilliseconds',
            {
                enumerable: true,
                get: () => {
                    accessorReadCount += 1;
                    return 1_893_456_000_000n;
                },
            },
        );
        expect(() => runtime.encodeActionDefinition(actionDefinition)).toThrow(
            TypeError,
        );

        const boardPolicy = {} as { boardOriginIdentifier: string };
        Object.defineProperty(boardPolicy, 'boardOriginIdentifier', {
            enumerable: true,
            get: () => {
                accessorReadCount += 1;
                return 'board.example.test';
            },
        });
        expect(() => runtime.encodeBoardPolicy(boardPolicy)).toThrow(TypeError);

        const ceremonyContext = {
            canonicalRosterBytes: new Uint8Array([2]),
            canonicalSuiteRecordBytes: new Uint8Array([3]),
            ceremonyIdentifier: 'ceremony',
            expectedSuiteId: zeroHash,
        } as {
            canonicalManifestBytes: Uint8Array;
            canonicalRosterBytes: Uint8Array;
            canonicalSuiteRecordBytes: Uint8Array;
            ceremonyIdentifier: string;
            expectedSuiteId: ProtocolHash;
        };
        Object.defineProperty(ceremonyContext, 'canonicalManifestBytes', {
            enumerable: true,
            get: () => {
                accessorReadCount += 1;
                return new Uint8Array([1]);
            },
        });
        expect(() => runtime.verifyCeremonyContext(ceremonyContext)).toThrow(
            TypeError,
        );
        expect(accessorReadCount).toBe(0);
    });

    it('uses each proxy data-property descriptor exactly once', () => {
        const observedRequests: unknown[] = [];
        const runtime = openRuntimeWithMethods({
            encodeFoundationActionDefinition: (request: unknown) => {
                observedRequests.push(request);
                return {
                    actionDefinitionHash: zeroHash,
                    canonicalBytesHex: '',
                };
            },
            encodeFoundationBoardPolicy: (request: unknown) => {
                observedRequests.push(request);
                return { boardPolicyHash: zeroHash, canonicalBytesHex: '' };
            },
            encodeFoundationManifest: (request: unknown) => {
                observedRequests.push(request);
                return { manifestHash: zeroHash, canonicalBytesHex: '' };
            },
            verifyFoundationCeremonyContext: (request: unknown) => {
                observedRequests.push(request);
                return refused;
            },
        });
        const descriptorCounts = new Map<string, number>();
        const proxySnapshot = <Value extends object>(
            value: Value,
            prefix: string,
        ): Value =>
            new Proxy(value, {
                get: () => {
                    throw new Error('ordinary property reads are not allowed');
                },
                getOwnPropertyDescriptor: (target, propertyName) => {
                    const key = `${prefix}.${String(propertyName)}`;
                    descriptorCounts.set(
                        key,
                        (descriptorCounts.get(key) ?? 0) + 1,
                    );
                    return Reflect.getOwnPropertyDescriptor(
                        target,
                        propertyName,
                    );
                },
            });

        runtime.encodeManifest(proxySnapshot(manifestInput(), 'manifest'));
        runtime.encodeActionDefinition(
            proxySnapshot(
                {
                    submissionCutoffUnixMilliseconds: 1_893_456_000_000n,
                    topCount: 7,
                },
                'action',
            ),
        );
        runtime.encodeBoardPolicy(
            proxySnapshot(
                { boardOriginIdentifier: 'board.example.test' },
                'board',
            ),
        );
        runtime.verifyCeremonyContext(
            proxySnapshot(
                {
                    canonicalManifestBytes: new Uint8Array([1]),
                    canonicalRosterBytes: new Uint8Array([2]),
                    canonicalSuiteRecordBytes: new Uint8Array([3]),
                    ceremonyIdentifier: 'ceremony',
                    expectedSuiteId: zeroHash,
                },
                'context',
            ),
        );

        expect(observedRequests).toHaveLength(4);
        expect([...descriptorCounts.values()]).toEqual(
            expect.arrayContaining(
                Array.from({ length: descriptorCounts.size }, () => 1),
            ),
        );
        expect(descriptorCounts).toEqual(
            new Map([
                ['manifest.displayTitle', 1],
                ['manifest.optionDefinitions', 1],
                ['action.submissionCutoffUnixMilliseconds', 1],
                ['action.topCount', 1],
                ['board.boardOriginIdentifier', 1],
                ['context.canonicalManifestBytes', 1],
                ['context.canonicalRosterBytes', 1],
                ['context.canonicalSuiteRecordBytes', 1],
                ['context.ceremonyIdentifier', 1],
                ['context.expectedSuiteId', 1],
            ]),
        );
    });

    it('refuses proxied and detached byte views before kernel dispatch', () => {
        const runtime = openRuntimeWithMethods({});
        const proxiedBytes = new Proxy(new Uint8Array([0x31]), {});

        for (const verify of [
            runtime.verifyManifest,
            runtime.verifyActionDefinition,
            runtime.verifyBoardPolicy,
            runtime.verifySuiteRecord,
        ]) {
            expect(() => verify(proxiedBytes)).toThrow(TypeError);
            expect(() => verify(detachBytes())).toThrow(TypeError);
        }

        expect(() =>
            runtime.verifyCeremonyContext({
                canonicalManifestBytes: detachBytes(),
                canonicalRosterBytes: new Uint8Array([2]),
                canonicalSuiteRecordBytes: new Uint8Array([3]),
                ceremonyIdentifier: 'ceremony',
                expectedSuiteId: zeroHash,
            }),
        ).toThrow(TypeError);
    });

    it('dispatches owned byte and record snapshots that caller mutation cannot alter', () => {
        const manifestBytes = new Uint8Array([0x01, 0x02]);
        const actionDefinitionBytes = new Uint8Array([0x03, 0x04]);
        const boardPolicyBytes = new Uint8Array([0x05, 0x06]);
        const suiteRecordBytes = new Uint8Array([0x07, 0x08]);
        const contextManifestBytes = new Uint8Array([0x09]);
        const contextRosterBytes = new Uint8Array([0x0a]);
        const contextSuiteBytes = new Uint8Array([0x0b]);
        const requests = new Map<string, Record<string, unknown>>();
        const runtime = openRuntimeWithMethods({
            verifyFoundationManifest: (request: Record<string, unknown>) => {
                requests.set('manifest', request);
                manifestBytes.fill(0xff);
                return refused;
            },
            verifyFoundationActionDefinition: (
                request: Record<string, unknown>,
            ) => {
                requests.set('action', request);
                actionDefinitionBytes.fill(0xff);
                return refused;
            },
            verifyFoundationBoardPolicy: (request: Record<string, unknown>) => {
                requests.set('board', request);
                boardPolicyBytes.fill(0xff);
                return refused;
            },
            verifyFoundationSuiteRecord: (request: Record<string, unknown>) => {
                requests.set('suite', request);
                suiteRecordBytes.fill(0xff);
                return refused;
            },
            verifyFoundationCeremonyContext: (
                request: Record<string, unknown>,
            ) => {
                requests.set('context', request);
                contextManifestBytes.fill(0xff);
                contextRosterBytes.fill(0xff);
                contextSuiteBytes.fill(0xff);
                return refused;
            },
        });

        runtime.verifyManifest(manifestBytes);
        runtime.verifyActionDefinition(actionDefinitionBytes);
        runtime.verifyBoardPolicy(boardPolicyBytes);
        runtime.verifySuiteRecord(suiteRecordBytes);
        runtime.verifyCeremonyContext({
            canonicalManifestBytes: contextManifestBytes,
            canonicalRosterBytes: contextRosterBytes,
            canonicalSuiteRecordBytes: contextSuiteBytes,
            ceremonyIdentifier: 'ceremony',
            expectedSuiteId: zeroHash,
        });

        expect(requests.get('manifest')).toEqual({ canonicalBytesHex: '0102' });
        expect(requests.get('action')).toEqual({ canonicalBytesHex: '0304' });
        expect(requests.get('board')).toEqual({ canonicalBytesHex: '0506' });
        expect(requests.get('suite')).toEqual({ canonicalBytesHex: '0708' });
        expect(requests.get('context')).toEqual({
            canonicalManifestBytesHex: '09',
            canonicalRosterBytesHex: '0a',
            canonicalSuiteRecordBytesHex: '0b',
            ceremonyIdentifier: 'ceremony',
            expectedSuiteId: zeroHash,
        });
    });
});

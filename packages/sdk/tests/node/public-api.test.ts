import { describe, expect, it } from 'vitest';

import * as publicApiRuntime from '../../dist/index.js';

type OpenParticipant = (options: {
    readonly namespace: string;
    readonly relay: string;
}) => { readonly run: unknown };
type VerifyOutcome = (options: {
    readonly poll: string;
    readonly relay: string;
}) => Promise<unknown>;
const publicApiRuntimeRecord = publicApiRuntime as Record<string, unknown>;
const openParticipant =
    publicApiRuntimeRecord.openParticipant as OpenParticipant;
const verifyOutcome = publicApiRuntimeRecord.verifyOutcome as VerifyOutcome;
const expectedPublicRuntimeExportNames = [
    'openParticipant',
    'verifyOutcome',
] as const;

describe('public package API in Node', () => {
    it('exposes safe runtime functions and keeps runtime exports callable', () => {
        const runtimeExportNames = Object.keys(publicApiRuntimeRecord).sort();

        expect(runtimeExportNames).toEqual(expectedPublicRuntimeExportNames);
        for (const publicFunctionName of runtimeExportNames) {
            expect(
                typeof publicApiRuntimeRecord[publicFunctionName],
                publicFunctionName,
            ).toBe('function');
        }
    });

    it('opens a participant only for a well-formed namespace and relay', () => {
        const relay = 'https://relay.example/polls/';
        for (const namespace of [
            '',
            'Poll',
            '-poll',
            'poll-',
            'poll/one',
            'poll one',
            'a'.repeat(65),
        ])
            expect(() => openParticipant({ namespace, relay })).toThrow(
                TypeError,
            );
        for (const malformed of [
            'relay.example/polls/',
            '/polls/',
            'ftp://relay.example/polls/',
            'https://relay.example/polls/?poll=1',
            'https://relay.example/polls/#poll',
            'https://user@relay.example/polls/',
        ])
            expect(() =>
                openParticipant({ namespace: 'poll', relay: malformed }),
            ).toThrow(TypeError);
        for (const namespace of ['a', '0-poll-9', 'a'.repeat(64)])
            expect(typeof openParticipant({ namespace, relay }).run).toBe(
                'function',
            );
        expect(
            typeof openParticipant({
                namespace: 'poll',
                relay: 'http://127.0.0.1:8080/polls',
            }).run,
        ).toBe('function');
    });

    it('verifies an outcome only for a well-formed poll identity and relay', async () => {
        const relay = 'https://relay.example/polls/';
        for (const poll of [
            '',
            'a'.repeat(126),
            'a'.repeat(130),
            'A'.repeat(128),
            'g'.repeat(128),
        ])
            await expect(verifyOutcome({ poll, relay })).rejects.toThrow(
                TypeError,
            );
        for (const malformed of [
            'relay.example/polls/',
            'ftp://relay.example/polls/',
            'https://relay.example/polls/?poll=1',
            'https://relay.example/polls/#poll',
            'https://user@relay.example/polls/',
        ])
            await expect(
                verifyOutcome({ poll: 'a'.repeat(128), relay: malformed }),
            ).rejects.toThrow(TypeError);
    });
});

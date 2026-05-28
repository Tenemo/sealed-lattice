import { describe, expect, it } from 'vitest';

import {
    protocolHashNamespaceValues,
    resolveProtocolHashDomain,
} from '#packages/crypto/src/index';
import { loadTranscriptCoreKernel } from '#packages/wasm/src/index';

describe('hash namespace parity', () => {
    it('matches TypeScript hash domains to the Rust kernel namespace list', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const typeScriptDomains = protocolHashNamespaceValues
            .map(resolveProtocolHashDomain)
            .sort();
        const rustDomains = Array.from(
            kernel.listReservedRootNamespaces(),
        ).sort();

        expect(typeScriptDomains).toEqual(rustDomains);
    });
});

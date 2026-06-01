import { describe, expect, it } from 'vitest';

import {
    protocolHashNamespaceValues,
    resolveProtocolHashDomain,
} from '#packages/crypto/src/index';
import { loadTranscriptCoreKernel } from '#packages/wasm/src/index';

describe('hash namespace registries', () => {
    it('lists valid TypeScript and Rust root namespaces without duplicates', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const typeScriptDomains = protocolHashNamespaceValues
            .map(resolveProtocolHashDomain)
            .sort();
        const rustDomains = Array.from(
            kernel.listReservedRootNamespaces(),
        ).sort();

        expect(new Set(typeScriptDomains).size).toBe(typeScriptDomains.length);
        expect(new Set(rustDomains).size).toBe(rustDomains.length);
        for (const domain of [...typeScriptDomains, ...rustDomains]) {
            expect(domain).toMatch(/^sealed-lattice-root\/[a-z0-9-]+-v1$/u);
        }
    });
});

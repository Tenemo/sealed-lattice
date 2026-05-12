import { describe, expect, it } from 'vitest';

import {
    protocolDigestNamespaceValues,
    resolveProtocolDigestDomain,
} from '../../packages/crypto/src/index';
import { loadTranscriptCoreKernel } from '../../packages/wasm/src/index';

describe('digest namespace parity', () => {
    it('matches TypeScript digest domains to the Rust kernel namespace list', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const typeScriptDomains = protocolDigestNamespaceValues
            .map(resolveProtocolDigestDomain)
            .sort();
        const rustDomains = Array.from(
            kernel.listReservedRootNamespaces(),
        ).sort();

        expect(typeScriptDomains).toEqual(rustDomains);
    });
});

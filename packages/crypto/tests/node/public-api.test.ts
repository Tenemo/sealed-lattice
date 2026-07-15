import { describe, expect, it } from 'vitest';

import * as cryptoPublicApi from '../../src/index.js';

describe('crypto package public API', () => {
    it('exposes the exact closed-operation runtime inventory', () => {
        expect(Object.keys(cryptoPublicApi).sort()).toEqual([
            'AuthenticatedMailboxCleanupError',
            'BrowserLocalKeyProviderError',
            'canonicalJson',
            'deriveCanonicalObjectHash',
            'hash512Hex',
            'openAuthenticatedMailbox',
            'openBrowserLocalExternalKeyProvider',
            'openCanonicalJsonByteSource',
            'sealAuthenticatedMailbox',
        ]);
    });
});

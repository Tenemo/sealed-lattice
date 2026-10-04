import {
    browserSha512,
    createBrowserProofReader,
    readBoundedBrowserResponse,
} from './seed-sharing-browser-input.mjs';
import { verifySeedSharingProof } from './seed-sharing-scalar-verifier.mjs';

/** @typedef {{moduleUrl:string,moduleBytes:number,moduleSha512:string,proofs:(import('./seed-sharing-browser-input.mjs').BrowserProof & import('./seed-sharing-scalar-verifier.mjs').Proof)[],probe:import('./seed-sharing-scalar-verifier.mjs').Probe}} Configuration */

self.onmessage = ({ data }) => {
    void (async () => {
        const { moduleUrl, moduleBytes, moduleSha512, proofs, probe } =
            /** @type {Configuration} */ (data);
        if (!isSecureContext || typeof crypto.subtle !== 'object')
            throw new Error(
                'The verification worker lacks secure browser hashing.',
            );
        const bytes = await readBoundedBrowserResponse(
            moduleUrl,
            moduleBytes,
            8_388_608,
        );
        if ((await browserSha512(bytes)) !== moduleSha512)
            throw new Error('The browser verifier module identity differs.');
        const proof = proofs[probe.proof];
        const result = await verifySeedSharingProof({
            moduleBytes: bytes,
            proof,
            probe,
            readExact: createBrowserProofReader(proof),
        });
        self.postMessage({ result });
    })().catch((error) => {
        self.postMessage({
            error: error instanceof Error ? error.message : String(error),
        });
    });
};

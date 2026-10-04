import {
    browserSha512,
    createBrowserProofReader,
    emitBrowserProofChunk,
    readBoundedBrowserResponse,
} from './seed-sharing-browser-input.mjs';
import { verifySeedSharingProof } from './seed-sharing-scalar-verifier.mjs';

/** @typedef {{moduleUrl:string,moduleBytes:number,moduleSha512:string,proofs:(import('./seed-sharing-browser-input.mjs').BrowserProof & import('./seed-sharing-scalar-verifier.mjs').Proof)[],probe:import('./seed-sharing-scalar-verifier.mjs').Probe}} VerificationConfiguration */

/** @typedef {{mode:'generate',moduleUrl:string,moduleBytes:number,moduleSha512:string,expectedBytes:number,sinkUrl:string}} GenerationConfiguration */

self.onmessage = ({ data }) => {
    void (async () => {
        const configuration =
            /** @type {VerificationConfiguration | GenerationConfiguration} */ (
                data
            );
        const { moduleUrl, moduleBytes, moduleSha512 } = configuration;
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
        let result;
        if ('mode' in configuration && configuration.mode === 'generate') {
            const { generateSeedSharingProof } =
                await import('./seed-sharing-scalar-prover.mjs');
            result = await generateSeedSharingProof({
                moduleBytes: bytes,
                expectedBytes: configuration.expectedBytes,
                emitChunk: (index, offset, chunk) =>
                    emitBrowserProofChunk(
                        configuration.sinkUrl,
                        index,
                        offset,
                        chunk,
                    ),
                onProgress: (progress) => self.postMessage({ progress }),
            });
        } else {
            const { proofs, probe } = /** @type {VerificationConfiguration} */ (
                configuration
            );
            const proof = proofs[probe.proof];
            result = await verifySeedSharingProof({
                moduleBytes: bytes,
                proof,
                probe,
                readExact: createBrowserProofReader(proof),
            });
        }
        self.postMessage({ result });
    })().catch((error) => {
        self.postMessage({
            error: error instanceof Error ? error.message : String(error),
        });
    });
};

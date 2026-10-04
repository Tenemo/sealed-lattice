import {
    browserSha512,
    createBrowserProofReader,
    createBrowserPredecessorReader,
    emitBrowserOutputChunk,
    readBoundedBrowserResponse,
} from './seed-sharing-browser-input.mjs';
import { verifyBoundedProof } from './seed-sharing-scalar-verifier.mjs';

/** @typedef {import('./seed-sharing-browser-input.mjs').BrowserProof & import('./scalar-proof-stream.mjs').Proof} BrowserProof */
/** @typedef {{moduleUrl:string,moduleBytes:number,moduleSha512:string,relation?:'seed-sharing'|'opening-share',predecessors?:BrowserProof[]}} SharedConfiguration */
/** @typedef {SharedConfiguration & {proofs:BrowserProof[],probe:import('./scalar-proof-stream.mjs').Probe}} VerificationConfiguration */

/** @typedef {SharedConfiguration & {mode:'generate',expectedBytes:number,sinkUrl:string}} GenerationConfiguration */
/** @typedef {{mode:'operator',screenKind:'public-operator'|'fhe-key-source',caseIndex:0|1,moduleUrl:string,moduleBytes:number,moduleSha512:string,expectedBytes:number,sinkUrl:string}} OperatorConfiguration */

self.onmessage = ({ data }) => {
    void (async () => {
        const configuration =
            /** @type {VerificationConfiguration | GenerationConfiguration | OperatorConfiguration} */ (
                data
            );
        const { moduleUrl, moduleBytes, moduleSha512 } = configuration;
        if (!isSecureContext || typeof crypto.subtle !== 'object')
            throw new Error(
                'The experiment worker lacks secure browser hashing.',
            );
        const bytes = await readBoundedBrowserResponse(
            moduleUrl,
            moduleBytes,
            8_388_608,
        );
        if ((await browserSha512(bytes)) !== moduleSha512)
            throw new Error('The browser module identity differs.');
        if ('mode' in configuration && configuration.mode === 'operator') {
            const { runPublicOperatorScreen, runFheKeySourceScreen } =
                await import('./public-operator-scalar.mjs');
            const result = await (
                configuration.screenKind === 'fhe-key-source'
                    ? runFheKeySourceScreen
                    : runPublicOperatorScreen
            )({
                moduleBytes: bytes,
                caseIndex: configuration.caseIndex,
                expectedBytes: configuration.expectedBytes,
                emitChunk: (index, offset, chunk) =>
                    emitBrowserOutputChunk(
                        configuration.sinkUrl,
                        index,
                        offset,
                        chunk,
                    ),
                onProgress: (progress) => self.postMessage({ progress }),
            });
            self.postMessage({ result });
            return;
        }
        const predecessors = configuration.predecessors ?? [];
        const predecessorReader = createBrowserPredecessorReader(predecessors);
        const relation = configuration.relation ?? 'seed-sharing';
        let result;
        if ('mode' in configuration && configuration.mode === 'generate') {
            const { generateBoundedProof } =
                await import('./seed-sharing-scalar-prover.mjs');
            result = await generateBoundedProof({
                moduleBytes: bytes,
                relation,
                predecessors,
                readPredecessor: predecessorReader.read,
                expectedBytes: configuration.expectedBytes,
                emitChunk: (index, offset, chunk) =>
                    emitBrowserOutputChunk(
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
            const readProof = createBrowserProofReader(proof);
            result = await verifyBoundedProof({
                moduleBytes: bytes,
                relation,
                predecessors,
                readPredecessor: predecessorReader.read,
                proof,
                probe,
                readExact: (length, position) => {
                    predecessorReader.release();
                    return readProof(length, position);
                },
            });
        }
        predecessorReader.release();
        self.postMessage({ result });
    })().catch((error) => {
        self.postMessage({
            error: error instanceof Error ? error.message : String(error),
        });
    });
};

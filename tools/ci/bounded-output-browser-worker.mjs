import {
    browserSha512,
    emitBrowserOutputChunk,
    readBoundedBrowserResponse,
} from './bounded-output-browser-transport.mjs';
import { runFheKeySourceScreen } from './fhe-key-source-scalar.mjs';

/** @typedef {{caseIndex:0,moduleUrl:string,moduleBytes:number,moduleSha512:string,expectedBytes:number,sinkUrl:string}} OperatorConfiguration */

self.onmessage = ({ data }) => {
    void (async () => {
        const configuration = /** @type {OperatorConfiguration} */ (data);
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
        const result = await runFheKeySourceScreen({
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
    })().catch((error) => {
        self.postMessage({
            error: error instanceof Error ? error.message : String(error),
        });
    });
};

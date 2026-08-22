export const nodeKernelProofEvidenceProjectName = 'node-kernel-proof-evidence';

export type NodeKernelProofEvidenceCase = Readonly<{
    caseIdentifier: string;
    testFilePath: string;
    testName: string;
}>;

export const compactPublicKeyWasmProofEvidenceCase = Object.freeze({
    caseIdentifier: 'compact-public-key-scalar-wasm-same-byte',
    testFilePath:
        'packages/wasm/tests/node/compact-public-key-wasm-proof-evidence.manual.kernel.test.ts',
    testName:
        'Compact public-key scalar WASM proof evidence > generates canonical reference bytes and verifies the same bytes in a fresh scalar instance',
} satisfies NodeKernelProofEvidenceCase);

export const nodeKernelProofEvidenceCases = Object.freeze([
    compactPublicKeyWasmProofEvidenceCase,
] satisfies readonly NodeKernelProofEvidenceCase[]);

export const manualNodeKernelProofEvidenceTestGlobs = Object.freeze(
    nodeKernelProofEvidenceCases.map(({ testFilePath }) => testFilePath),
);

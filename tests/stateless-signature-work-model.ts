// FIPS 205 Table 2, SLH-DSA-256f. Work is derived from Algorithms 5-20;
// it is a candidate screen, not an authentication-format selection.
const statelessSignatureParameters = {
    nodeBytes: 32n,
    totalHeight: 68n,
    layers: 17n,
    forestHeight: 9n,
    forestTrees: 35n,
    logWinternitz: 4n,
    digestBytes: 49n,
} as const;

export const compileStatelessSignatureWork = () => {
    const parameters = statelessSignatureParameters;
    const winternitz = 1n << parameters.logWinternitz;
    const messageChains =
        (8n * parameters.nodeBytes) / parameters.logWinternitz;
    let checksumChains = 0n;
    for (
        let value = messageChains * (winternitz - 1n);
        value > 0n;
        value /= winternitz
    )
        checksumChains++;
    const chains = messageChains + checksumChains;
    const layerHeight = parameters.totalHeight / parameters.layers;
    const layerLeaves = 1n << layerHeight;
    const forestLeaves = 1n << parameters.forestHeight;
    const tree = {
        pseudorandomFunction: layerLeaves * chains,
        chainHash: layerLeaves * chains * (winternitz - 1n),
        parentHash: layerLeaves - 1n,
        chainCompression: layerLeaves,
    };
    return {
        ...parameters,
        winternitz,
        chains,
        layerHeight,
        layerLeaves,
        forestLeaves,
        publicKeyBytes: 2n * parameters.nodeBytes,
        secretKeyBytes: 4n * parameters.nodeBytes,
        signatureBytes:
            parameters.nodeBytes *
            (1n +
                parameters.forestTrees * (parameters.forestHeight + 1n) +
                parameters.layers * (chains + layerHeight)),
        keyGeneration: tree,
        // Signing reconstructs every lower root. The top layer omits final
        // public-key recovery; its message-dependent chain suffix is unneeded.
        signing: {
            pseudorandomFunction:
                parameters.forestTrees * forestLeaves +
                parameters.layers * tree.pseudorandomFunction,
            chainHashUpper:
                parameters.forestTrees * forestLeaves +
                parameters.layers * tree.chainHash,
            parentHash:
                parameters.forestTrees * (forestLeaves - 1n) +
                parameters.layers * tree.parentHash -
                layerHeight,
            chainCompression: parameters.layers * tree.chainCompression - 1n,
            forestCompression: 1n,
            messageRandomization: 1n,
            messageHash: 1n,
        },
        verification: {
            chainHashUpper:
                parameters.forestTrees +
                parameters.layers * chains * (winternitz - 1n),
            parentHash:
                parameters.forestTrees * parameters.forestHeight +
                parameters.totalHeight,
            chainCompression: parameters.layers,
            forestCompression: 1n,
            messageHash: 1n,
        },
    };
};

// Literal initialization in the inspected formal reduction, not work done by
// the deployed signature algorithm. Count symbolically; never allocate it.
export const compileStatelessSignatureProofWork = (signingQueries: bigint) => {
    if (signingQueries < 0n)
        throw new RangeError('Negative signing-query count.');
    const work = compileStatelessSignatureWork();
    const forestInstances = 1n << work.totalHeight;
    const forestSecretElements =
        forestInstances * work.forestTrees * work.forestLeaves;
    let chainSecretElements = 0n;
    for (let layer = 0n; layer < work.layers; layer++) {
        const instances = 1n << (work.totalHeight - layer * work.layerHeight);
        chainSecretElements += instances * work.chains;
    }
    const secretElements = forestSecretElements + chainSecretElements;
    return {
        forestInstances,
        forestSecretElements,
        chainSecretElements,
        secretElements,
        secretPayloadBytes: secretElements * work.nodeBytes,
        // A PRF-substitution hop with ordinary classical calls can follow the
        // actual signing schedule. This does not rewrite the separate THF
        // games whose target-registration phase ends before the public seed.
        demandSecretOracleCallsUpper:
            work.keyGeneration.pseudorandomFunction +
            signingQueries * work.signing.pseudorandomFunction,
        demandMessageOracleCallsUpper: signingQueries,
    };
};

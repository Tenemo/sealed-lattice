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

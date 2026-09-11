import { compileStatelessSignatureWork } from '#tests/stateless-signature-work-model.js';

const work = compileStatelessSignatureWork(),
    nodeBytes = Number(work.nodeBytes);
// Internal random-table addresses for the fixed standard parameter set.
// Kinds distinguish chain nodes, compressed WOTS keys, XMSS nodes, FORS
// secrets, FORS nodes and FORS keys. These are not participant carriers.
export const nodeLabel = (
    kind: number,
    seed: Uint8Array,
    layer: number,
    tree: bigint,
    leaf: number,
    first = 0,
    second = 0,
) => {
    const label = Buffer.alloc(61);
    label[0] = kind;
    label.set(seed, 1);
    label.writeUInt32BE(layer, 33);
    label.writeBigUInt64BE(tree, 41);
    label.writeUInt32BE(leaf, 49);
    label.writeUInt32BE(first, 53);
    label.writeUInt32BE(second, 57);
    return label;
};
export const readNodeLabel = (label: Buffer) => {
    if (label.length !== 61) throw new RangeError('Wrong node label width.');
    return {
        kind: label[0],
        seed: label.subarray(1, 33),
        layer: label.readUInt32BE(33),
        tree: label.readBigUInt64BE(41),
        leaf: label.readUInt32BE(49),
        first: label.readUInt32BE(53),
        second: label.readUInt32BE(57),
    };
};
export const routeSignatureHashRow = (input: Buffer) => {
    if (input.length < nodeBytes + 32) return;
    const seed = input.subarray(0, nodeBytes),
        adrs = input.subarray(nodeBytes, nodeBytes + 32),
        layer = adrs.readUInt32BE(0),
        tree = adrs.readBigUInt64BE(8),
        type = adrs.readUInt32BE(16),
        leaf = adrs.readUInt32BE(20),
        first = adrs.readUInt32BE(24),
        second = adrs.readUInt32BE(28),
        payloadBytes = input.length - nodeBytes - 32;
    if (
        layer >= Number(work.layers) ||
        adrs.readUInt32BE(4) !== 0 ||
        tree >=
            1n << (work.totalHeight - (BigInt(layer) + 1n) * work.layerHeight)
    )
        return;
    const label = (
        kind: number,
        keyPair: number,
        firstArgument = 0,
        secondArgument = 0,
    ) =>
        nodeLabel(
            kind,
            seed,
            layer,
            tree,
            keyPair,
            firstArgument,
            secondArgument,
        );
    const leafFits = leaf < Number(work.layerLeaves),
        wotsHeight = Number(work.layerHeight),
        forestHeight = Number(work.forestHeight);
    const xmss = (height: number, index: number) =>
        height === 0 ? label(1, index) : label(2, 0, height, index);
    let target: Buffer, dependencies: Buffer[];
    if (
        type === 0 &&
        payloadBytes === nodeBytes &&
        leafFits &&
        first < Number(work.chains) &&
        second < Number(work.winternitz) - 1
    ) {
        target = label(0, leaf, first, second + 1);
        dependencies = [label(0, leaf, first, second)];
    } else if (
        type === 1 &&
        payloadBytes === Number(work.chains) * nodeBytes &&
        leafFits &&
        first === 0 &&
        second === 0
    ) {
        target = label(1, leaf);
        dependencies = Array.from({ length: Number(work.chains) }, (_, index) =>
            label(0, leaf, index, Number(work.winternitz) - 1),
        );
    } else if (
        type === 2 &&
        payloadBytes === 2 * nodeBytes &&
        leaf === 0 &&
        first >= 1 &&
        first <= wotsHeight &&
        second < 2 ** (wotsHeight - first)
    ) {
        target = xmss(first, second);
        dependencies = [
            xmss(first - 1, 2 * second),
            xmss(first - 1, 2 * second + 1),
        ];
    } else if (
        type === 3 &&
        layer === 0 &&
        leafFits &&
        first === 0 &&
        payloadBytes === nodeBytes &&
        second < Number(work.forestTrees * work.forestLeaves)
    ) {
        target = label(4, leaf, 0, second);
        dependencies = [label(3, leaf, 0, second)];
    } else if (
        type === 3 &&
        layer === 0 &&
        leafFits &&
        first >= 1 &&
        first <= forestHeight &&
        payloadBytes === 2 * nodeBytes &&
        second < Number(work.forestTrees) * 2 ** (forestHeight - first)
    ) {
        target = label(4, leaf, first, second);
        dependencies = [
            label(4, leaf, first - 1, 2 * second),
            label(4, leaf, first - 1, 2 * second + 1),
        ];
    } else if (
        type === 4 &&
        layer === 0 &&
        leafFits &&
        payloadBytes === Number(work.forestTrees) * nodeBytes &&
        first === 0 &&
        second === 0
    ) {
        target = label(5, leaf);
        dependencies = Array.from(
            { length: Number(work.forestTrees) },
            (_, index) => label(4, leaf, forestHeight, index),
        );
    } else return;
    const stageMessage =
        type === 0
            ? layer === 0
                ? label(5, leaf)
                : nodeLabel(
                      2,
                      seed,
                      layer - 1,
                      (tree << work.layerHeight) | BigInt(leaf),
                      0,
                      wotsHeight,
                      0,
                  )
            : undefined;
    return {
        target,
        dependencies,
        stageMessage,
        payload: input.subarray(nodeBytes + 32),
        type,
        seed,
        layer,
        tree,
        leaf,
        first,
        second,
    };
};

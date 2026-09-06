// Each opening expands only opaque subtrees not authenticated by an earlier
// opening. The leaf order and tree size fix every transmitted sibling position.
export const merklePathSharingSchedule = (
    length: number,
    indices: readonly number[],
) => {
    if (
        !Number.isSafeInteger(length) ||
        length < 2 ||
        !Number.isInteger(Math.log2(length)) ||
        length > 2 ** 30 ||
        indices.length === 0 ||
        indices.some(
            (index, position) =>
                !Number.isSafeInteger(index) ||
                index < 0 ||
                index >= length ||
                (position > 0 && index <= indices[position - 1]),
        )
    )
        throw new Error('Invalid canonical opening indices.');
    const authenticated = new Set<number>();
    const openings = indices.map((index) => {
        const siblings: number[] = [];
        let node = length + index;
        while (node > 1 && !authenticated.has(node)) {
            authenticated.add(node);
            const sibling = node % 2 === 0 ? node + 1 : node - 1;
            if (!authenticated.has(sibling)) {
                siblings.push(sibling);
                authenticated.add(sibling);
            }
            node = Math.floor(node / 2);
        }
        return { index, siblings, authenticatedAncestor: node };
    });
    return {
        openings,
        siblingCount: openings.reduce(
            (sum, opening) => sum + opening.siblings.length,
            0,
        ),
        cachedNodeCount: authenticated.size,
    };
};

export const maximumSharedPathSiblings = (length: number, count: number) => {
    if (
        !Number.isSafeInteger(length) ||
        length < 2 ||
        !Number.isInteger(Math.log2(length)) ||
        length > 2 ** 30 ||
        !Number.isSafeInteger(count) ||
        count < 1 ||
        count > length
    )
        throw new Error('Invalid Merkle tree or opening count.');
    let maximum = 0;
    for (let parents = length / 2; parents >= 1; parents /= 2)
        maximum += Math.min(count, parents);
    return maximum;
};

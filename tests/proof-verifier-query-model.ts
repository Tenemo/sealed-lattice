import { compileCommonAgreementDegreeCensus } from '#tests/common-agreement-degree-model.js';
import {
    maximumSharedPathSiblings,
    merklePathSharingSchedule,
} from '#tests/merkle-path-sharing-model.js';

export const merkleVerificationQueries = (
    length: number,
    indices: readonly number[],
) => {
    const schedule = merklePathSharingSchedule(length, indices);
    const leafDepth = Math.log2(length);
    const nodeQueries = schedule.openings.reduce(
        (total, opening) =>
            total +
            leafDepth -
            Math.floor(Math.log2(opening.authenticatedAncestor)),
        0,
    );
    return { leafQueries: indices.length, nodeQueries };
};

export const compileProofVerifierQueryCensus = () => {
    const profile = compileCommonAgreementDegreeCensus();
    const folds = Math.log2(profile.domainSize / 2);
    const lengths = [
        profile.domainSize,
        profile.domainSize,
        profile.domainSize,
    ];
    for (let length = profile.domainSize / 2; length > 2; length /= 2)
        lengths.push(length);
    const groups = lengths.map((length) => {
        const maximumLeaves = Math.min(2 * profile.queries, length);
        return {
            length,
            maximumLeafQueries: maximumLeaves,
            maximumNodeQueries: maximumSharedPathSiblings(
                length,
                maximumLeaves,
            ),
        };
    });
    const maximumLeafQueries = groups.reduce(
        (sum, group) => sum + group.maximumLeafQueries,
        0,
    );
    const maximumNodeQueries = groups.reduce(
        (sum, group) => sum + group.maximumNodeQueries,
        0,
    );
    const verifierMessageQueries = folds + 4;
    const chainStateQueries = folds + 3;
    const messageRootQueries = folds + 3;
    const contextQueries = 1;
    return {
        groups,
        maximumLeafQueries,
        maximumNodeQueries,
        verifierMessageQueries,
        chainStateQueries,
        messageRootQueries,
        contextQueries,
        maximumCoreQueries:
            maximumLeafQueries +
            maximumNodeQueries +
            verifierMessageQueries +
            chainStateQueries +
            messageRootQueries +
            contextQueries,
        // One canonical verifier attempt. Statement reconstruction, common
        // matrix generation, outer authentication and additional attempts are
        // separate callers/queries, not silently covered by this subtotal.
    };
};

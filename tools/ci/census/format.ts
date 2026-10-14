export const formatCount = (value: bigint | number): string =>
    `\`${value.toLocaleString('en-US')}\``;

export const table = (
    header: readonly string[],
    rows: readonly (readonly string[])[],
): string =>
    [
        `| ${header.join(' | ')} |`,
        `| ${header.map(() => '---').join(' | ')} |`,
        ...rows.map((row) => `| ${row.join(' | ')} |`),
    ].join('\n');

// The whole base-two logarithm of further work, or none when the priced work
// alone already exceeds the level.
export const formatWorkAllowance = (allowance: bigint): string =>
    allowance > 0n ? formatCount(allowance.toString(2).length - 1) : 'none';

export const formatLog2Cost = (value: number): string =>
    Number.isFinite(value) ? `\`${value.toFixed(2)}\`` : 'no finite cost';

export const formatPopulationLimit = (limit: bigint | undefined): string =>
    limit === undefined ? 'none' : formatCount(limit);

export const distinctJoined = (values: readonly (bigint | number)[]): string =>
    [...new Set(values.map((value) => value.toString()))]
        .map((value) => formatCount(BigInt(value)))
        .join(', ');

export const rangeOf = (values: readonly (bigint | number)[]): string => {
    const sorted = values
        .map((value) => BigInt(value))
        .sort((left, right) => (left < right ? -1 : left > right ? 1 : 0));
    const [low, high] = [sorted[0], sorted[sorted.length - 1]];
    return low === high
        ? formatCount(low)
        : `${formatCount(low)} to ${formatCount(high)}`;
};

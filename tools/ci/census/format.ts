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

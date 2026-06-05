export const isRecord = (value: unknown): value is Record<string, unknown> =>
    typeof value === 'object' && value !== null;

export const isUsableDuration = (value: unknown): value is number =>
    typeof value === 'number' && Number.isFinite(value) && value >= 0;

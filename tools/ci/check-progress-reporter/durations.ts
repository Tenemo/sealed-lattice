export const checkCommandTimingKey = (
    laneName: string,
    commandDescription: string,
): string => `${laneName}\u0000${commandDescription}`;

export const formatProgressDuration = (
    durationMilliseconds: number,
): string => {
    const durationSeconds = durationMilliseconds / 1000;
    if (durationSeconds < 60) {
        return `${durationSeconds.toFixed(1)}s`;
    }

    const wholeSeconds = Math.round(durationSeconds);
    const minutes = Math.floor(wholeSeconds / 60);
    const seconds = wholeSeconds % 60;

    return `${minutes}m${String(seconds).padStart(2, '0')}s`;
};

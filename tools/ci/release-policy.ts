export type ReleaseCommandProbe = {
    readonly exitCode: number;
    readonly stderr: string;
    readonly stdout: string;
};

type NpmPublicationDisposition = 'already-identical' | 'publish';

type GitHubReleaseDisposition = 'already-exists' | 'create';

const publicPackageManifestPath = 'packages/sdk/package.json';

const formatProbeOutput = (probe: ReleaseCommandProbe): string => {
    const output = [probe.stdout.trim(), probe.stderr.trim()]
        .filter((entry) => entry.length > 0)
        .join('\n');
    return output.length > 0 ? output : '(no command output)';
};

const isNpmNotFoundProbe = (probe: ReleaseCommandProbe): boolean =>
    probe.exitCode !== 0 && `${probe.stdout}\n${probe.stderr}`.includes('E404');

const parseJsonString = (jsonText: string, description: string): string => {
    let parsedValue: unknown;
    try {
        parsedValue = JSON.parse(jsonText) as unknown;
    } catch {
        throw new Error(`${description} returned malformed JSON.`);
    }

    if (typeof parsedValue !== 'string' || parsedValue.length === 0) {
        throw new Error(`${description} did not return a non-empty string.`);
    }
    return parsedValue;
};

const parseJsonObject = (
    jsonText: string,
    description: string,
): Record<string, unknown> => {
    let parsedValue: unknown;
    try {
        parsedValue = JSON.parse(jsonText) as unknown;
    } catch {
        throw new Error(`${description} returned malformed JSON.`);
    }

    if (
        typeof parsedValue !== 'object' ||
        parsedValue === null ||
        Array.isArray(parsedValue)
    ) {
        throw new Error(`${description} did not return a JSON object.`);
    }
    return parsedValue as Record<string, unknown>;
};

export const validateUnmovedDefaultBranch = (input: {
    readonly defaultBranch: string;
    readonly remoteRevision: string;
    readonly sourceRevision: string;
}): void => {
    if (input.remoteRevision !== input.sourceRevision) {
        throw new Error(
            `origin/${input.defaultBranch} moved during release preparation. Start a new release.`,
        );
    }
};

export const validateCheckedOutReleaseCommit = (input: {
    readonly checkedOutRevision: string;
    readonly releaseRevision: string;
    readonly tag: string;
}): void => {
    if (input.checkedOutRevision !== input.releaseRevision) {
        throw new Error(
            `Tag ${input.tag} does not resolve to the release commit ${input.releaseRevision}.`,
        );
    }
};

export const validateReleaseMetadataPaths = (input: {
    readonly changedPaths: readonly string[];
    readonly untrackedPaths: readonly string[];
}): void => {
    if (!input.changedPaths.includes(publicPackageManifestPath)) {
        throw new Error(
            'Release metadata is missing the public package version change.',
        );
    }

    const unexpectedChangedPath = input.changedPaths.find(
        (changedPath) => changedPath !== publicPackageManifestPath,
    );
    if (unexpectedChangedPath !== undefined) {
        throw new Error(
            `Unexpected release metadata change: ${unexpectedChangedPath}`,
        );
    }

    if (input.untrackedPaths.length > 0) {
        throw new Error(
            `Release preparation produced unexpected untracked file: ${input.untrackedPaths[0]}`,
        );
    }
};

export const requireUnusedReleaseTag = (
    tag: string,
    tagLookup: ReleaseCommandProbe,
): void => {
    if (tagLookup.exitCode === 0) {
        throw new Error(`Tag ${tag} already exists.`);
    }
    if (tagLookup.exitCode !== 2) {
        throw new Error(
            `Could not verify the remote tag target:\n${formatProbeOutput(tagLookup)}`,
        );
    }
};

export const requireUnpublishedNpmVersion = (
    packageVersion: string,
    versionLookup: ReleaseCommandProbe,
): void => {
    if (versionLookup.exitCode === 0) {
        throw new Error(
            `sealed-lattice@${packageVersion} already exists on npm.`,
        );
    }
    if (!isNpmNotFoundProbe(versionLookup)) {
        throw new Error(
            `Could not verify the npm release target:\n${formatProbeOutput(versionLookup)}`,
        );
    }
};

export const resolveNpmPublication = (input: {
    readonly latestTagLookup?: ReleaseCommandProbe;
    readonly localIntegrity: string;
    readonly packageVersion: string;
    readonly registryLookup: ReleaseCommandProbe;
}): NpmPublicationDisposition => {
    if (input.registryLookup.exitCode === 0) {
        const registryIntegrity = parseJsonString(
            input.registryLookup.stdout,
            'The npm integrity lookup',
        );
        if (registryIntegrity !== input.localIntegrity) {
            throw new Error(
                `npm already contains different bytes for sealed-lattice@${input.packageVersion}.`,
            );
        }
        if (input.latestTagLookup === undefined) {
            throw new Error(
                'The npm latest dist-tag lookup was not performed for the existing release.',
            );
        }
        if (input.latestTagLookup.exitCode !== 0) {
            throw new Error(
                `Could not verify the npm latest dist-tag:\n${formatProbeOutput(input.latestTagLookup)}`,
            );
        }
        const latestVersion = parseJsonString(
            input.latestTagLookup.stdout,
            'The npm latest dist-tag lookup',
        );
        if (latestVersion !== input.packageVersion) {
            throw new Error(
                `npm latest points to sealed-lattice@${latestVersion}; expected sealed-lattice@${input.packageVersion}.`,
            );
        }
        return 'already-identical';
    }

    if (isNpmNotFoundProbe(input.registryLookup)) {
        return 'publish';
    }

    throw new Error(
        `Could not verify npm publication state:\n${formatProbeOutput(input.registryLookup)}`,
    );
};

export const resolveGitHubRelease = (input: {
    readonly releaseLookup: ReleaseCommandProbe;
    readonly tag: string;
}): GitHubReleaseDisposition => {
    if (input.releaseLookup.exitCode === 0) {
        const release = parseJsonObject(
            input.releaseLookup.stdout,
            'The GitHub release lookup',
        );
        if (
            release.tag_name !== input.tag ||
            release.draft !== false ||
            release.prerelease !== false
        ) {
            throw new Error(
                `GitHub release ${input.tag} exists but is not an ordinary release for the expected tag.`,
            );
        }
        return 'already-exists';
    }

    if (
        `${input.releaseLookup.stdout}\n${input.releaseLookup.stderr}`.includes(
            'HTTP 404',
        )
    ) {
        return 'create';
    }

    throw new Error(
        `Could not verify GitHub release state for ${input.tag}:\n${formatProbeOutput(input.releaseLookup)}`,
    );
};

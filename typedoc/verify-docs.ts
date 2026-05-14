import { promises as fs } from 'node:fs';
import path from 'node:path';

import {
    Application,
    Comment,
    ReflectionKind,
    type DeclarationReflection,
    type ProjectReflection,
} from 'typedoc';

import publicSurface from '../packages/sdk/public-surface.json' with { type: 'json' };
import { collectFiles, isWithinDirectory } from '../tools/internal/files.js';
import config from '../typedoc.config.mjs';

import {
    apiNavigationPath,
    apiReferenceRoot,
    docsContentRoot,
    publicApiReferenceEntries,
} from './public-api-reference';

const repoRoot = process.cwd();
const docsRoot = path.resolve(repoRoot, docsContentRoot);
const publicRoot = path.resolve(repoRoot, 'docs/public');
const referenceRoot = path.resolve(repoRoot, apiReferenceRoot);
const markdownRoots = ['README.md', docsContentRoot];
const documentedPublicApiEntries = publicApiReferenceEntries as readonly {
    apiReferencePagePath: string;
    moduleName: string;
}[];
const toPosixPath = (value: string): string => value.replace(/\\/g, '/');
const expectedGeneratedApiPagePaths = new Set([
    'index.md',
    ...documentedPublicApiEntries.map((entry) =>
        toPosixPath(
            path.relative(apiReferenceRoot, entry.apiReferencePagePath),
        ),
    ),
]);
const expectedGeneratedApiNavigationPaths = new Map(
    documentedPublicApiEntries.map((entry) => [
        toPosixPath(
            path.relative(apiReferenceRoot, entry.apiReferencePagePath),
        ),
        entry.moduleName,
    ]),
);
const requiredApiEntryPages = [
    `${docsContentRoot}/api/index.mdx`,
    ...documentedPublicApiEntries.map((entry) => entry.apiReferencePagePath),
    apiNavigationPath,
] as const;

const markdownLinkPattern = /!?\[[^\]]*]\(([^)]+)\)/g;
const linkTargetPattern = /^([^\s]+)(?:\s+["'][^"']*["'])?$/;
const htmlHrefPattern = /\bhref=(["'])(.*?)\1/g;
const frontmatterLinkPattern = /\blink:\s*("[^"]+"|'[^']+'|[^\s]+)/g;

const isExternalLink = (target: string): boolean =>
    target.startsWith('#') ||
    target.startsWith('//') ||
    /^[a-z][a-z0-9+.-]*:/i.test(target);

const normalizeLinkTarget = (rawTarget: string): string => {
    const trimmed = rawTarget.trim().replace(/^<|>$/g, '');
    const withoutWrappingQuotes =
        (trimmed.startsWith('"') && trimmed.endsWith('"')) ||
        (trimmed.startsWith("'") && trimmed.endsWith("'"))
            ? trimmed.slice(1, -1)
            : trimmed;
    const match = linkTargetPattern.exec(withoutWrappingQuotes);

    return (match?.[1] ?? withoutWrappingQuotes)
        .split('#', 1)[0]
        .split('?', 1)[0];
};

const isBaseUnsafeLinkTarget = (target: string): boolean =>
    target.startsWith('/') && !target.startsWith('//');

const toRepoRelativePath = (absolutePath: string): string =>
    toPosixPath(path.relative(repoRoot, absolutePath));

const isDocsContentFile = (candidate: string): boolean =>
    isWithinDirectory(docsRoot, candidate);

const isDocsRouteLink = (
    fromFile: string,
    normalizedTarget: string,
): boolean => {
    const isAbsoluteDocsRoute =
        normalizedTarget === '/' ||
        normalizedTarget.startsWith('/guides/') ||
        normalizedTarget.startsWith('/spec/') ||
        normalizedTarget.startsWith('/api/');
    if (normalizedTarget.startsWith('/')) {
        return isAbsoluteDocsRoute;
    }

    if (!isDocsContentFile(fromFile)) {
        return false;
    }

    const extension = path.extname(normalizedTarget).toLowerCase();

    return (
        normalizedTarget.endsWith('/') ||
        extension === '' ||
        extension === '.md' ||
        extension === '.mdx'
    );
};

const toDocsRoutePath = (absolutePath: string): string => {
    const normalizedPath = path.posix.normalize(
        toPosixPath(path.relative(docsRoot, absolutePath)),
    );

    if (normalizedPath === 'index.md' || normalizedPath === 'index.mdx') {
        return '/';
    }

    if (normalizedPath.endsWith('/index.md')) {
        return `/${normalizedPath.slice(0, -'index.md'.length)}`;
    }

    if (normalizedPath.endsWith('/index.mdx')) {
        return `/${normalizedPath.slice(0, -'index.mdx'.length)}`;
    }

    if (normalizedPath.endsWith('.md')) {
        return `/${normalizedPath.slice(0, -'.md'.length)}/`;
    }

    if (normalizedPath.endsWith('.mdx')) {
        return `/${normalizedPath.slice(0, -'.mdx'.length)}/`;
    }

    return `/${normalizedPath.replace(/\/+$/u, '')}/`;
};

const stripMarkdownRouteExtension = (target: string): string => {
    if (target.endsWith('.md') || target.endsWith('.mdx')) {
        return target.slice(0, -path.posix.extname(target).length);
    }

    return target;
};

const normalizeDocsRouteTarget = (target: string): string => {
    const withoutExtension = stripMarkdownRouteExtension(target);
    const withoutIndex = withoutExtension.endsWith('/index')
        ? withoutExtension.slice(0, -'/index'.length)
        : withoutExtension;

    if (withoutIndex === '/') {
        return '/';
    }

    return `${withoutIndex.replace(/\/+$/u, '')}/`;
};

const resolveDocsRouteTarget = (
    fromFile: string,
    normalizedTarget: string,
): string | undefined => {
    if (!isDocsRouteLink(fromFile, normalizedTarget)) {
        return undefined;
    }

    if (normalizedTarget.startsWith('/')) {
        return normalizeDocsRouteTarget(normalizedTarget);
    }

    const routeBase = toDocsRoutePath(fromFile);
    const absoluteRoute = path.posix.resolve(
        routeBase,
        stripMarkdownRouteExtension(normalizedTarget),
    );

    return normalizeDocsRouteTarget(absoluteRoute);
};

const fileExists = async (candidate: string): Promise<boolean> => {
    try {
        const stats = await fs.stat(candidate);
        return stats.isFile();
    } catch {
        return false;
    }
};

const resolveLinkCandidates = (
    fromFile: string,
    normalizedTarget: string,
): string[] => {
    const fromDocsRoute =
        normalizedTarget === '/' ||
        normalizedTarget.startsWith('/guides/') ||
        normalizedTarget.startsWith('/spec/') ||
        normalizedTarget.startsWith('/api/');
    const absoluteTarget = normalizedTarget.startsWith('/')
        ? normalizedTarget === '/'
            ? docsRoot
            : path.resolve(
                  fromDocsRoute ? docsRoot : repoRoot,
                  normalizedTarget === '/' ? '.' : normalizedTarget.slice(1),
              )
        : path.resolve(path.dirname(fromFile), normalizedTarget);
    const extension = path.extname(absoluteTarget).toLowerCase();
    const candidates = new Set<string>([absoluteTarget]);

    if (normalizedTarget.endsWith('/')) {
        candidates.add(`${absoluteTarget}.md`);
        candidates.add(`${absoluteTarget}.mdx`);
        candidates.add(path.join(absoluteTarget, 'index.md'));
        candidates.add(path.join(absoluteTarget, 'index.mdx'));
        candidates.add(path.join(absoluteTarget, 'README.md'));
    }

    if (extension === '') {
        candidates.add(`${absoluteTarget}.md`);
        candidates.add(`${absoluteTarget}.mdx`);
        candidates.add(path.join(absoluteTarget, 'index.md'));
        candidates.add(path.join(absoluteTarget, 'index.mdx'));
        candidates.add(path.join(absoluteTarget, 'README.md'));
    }

    if (extension === '.html') {
        if (normalizedTarget.startsWith('/')) {
            candidates.add(path.resolve(publicRoot, normalizedTarget.slice(1)));
        }
        candidates.add(
            path.join(
                path.dirname(absoluteTarget),
                `${path.basename(absoluteTarget, '.html')}.md`,
            ),
        );
        candidates.add(
            path.join(
                path.dirname(absoluteTarget),
                `${path.basename(absoluteTarget, '.html')}.mdx`,
            ),
        );
    }

    return [...candidates];
};

const collectMarkdownFiles = async (entry: string): Promise<string[]> =>
    collectFiles(path.resolve(repoRoot, entry), {
        extensions: ['.md', '.mdx'],
    });

const verifyLinks = async (): Promise<string[]> => {
    const markdownFiles = (
        await Promise.all(
            markdownRoots.map((entry) => collectMarkdownFiles(entry)),
        )
    ).flat();
    const docsRoutes = new Set(
        markdownFiles
            .filter(isDocsContentFile)
            .map((file) => toDocsRoutePath(file)),
    );
    const failures: string[] = [];

    for (const file of markdownFiles) {
        const content = await fs.readFile(file, 'utf8');
        for (const match of content.matchAll(markdownLinkPattern)) {
            const normalizedTarget = normalizeLinkTarget(match[1]);
            if (normalizedTarget === '' || isExternalLink(normalizedTarget)) {
                continue;
            }

            const docsRouteTarget = resolveDocsRouteTarget(
                file,
                normalizedTarget,
            );
            if (docsRouteTarget !== undefined) {
                if (!docsRoutes.has(docsRouteTarget)) {
                    failures.push(
                        `${toRepoRelativePath(file)} -> ${normalizedTarget}`,
                    );
                }
                continue;
            }

            const candidates = resolveLinkCandidates(file, normalizedTarget);
            let resolved = false;
            for (const candidate of candidates) {
                if (await fileExists(candidate)) {
                    resolved = true;
                    break;
                }
            }

            if (!resolved) {
                failures.push(
                    `${toRepoRelativePath(file)} -> ${normalizedTarget}`,
                );
            }
        }
    }

    return failures;
};

const verifyBaseAwareLinks = async (): Promise<string[]> => {
    const markdownFiles = await collectMarkdownFiles(docsContentRoot);
    const failures: string[] = [];

    for (const file of markdownFiles) {
        const content = await fs.readFile(file, 'utf8');
        const lines = content.split(/\r?\n/u);

        lines.forEach((line, index) => {
            for (const match of line.matchAll(markdownLinkPattern)) {
                const normalizedTarget = normalizeLinkTarget(match[1]);
                if (isBaseUnsafeLinkTarget(normalizedTarget)) {
                    failures.push(
                        `${toRepoRelativePath(file)}:${index + 1} -> ${normalizedTarget}`,
                    );
                }
            }

            for (const match of line.matchAll(htmlHrefPattern)) {
                const normalizedTarget = normalizeLinkTarget(match[2]);
                if (isBaseUnsafeLinkTarget(normalizedTarget)) {
                    failures.push(
                        `${toRepoRelativePath(file)}:${index + 1} -> ${normalizedTarget}`,
                    );
                }
            }

            for (const match of line.matchAll(frontmatterLinkPattern)) {
                const normalizedTarget = normalizeLinkTarget(match[1]);
                if (isBaseUnsafeLinkTarget(normalizedTarget)) {
                    failures.push(
                        `${toRepoRelativePath(file)}:${index + 1} -> ${normalizedTarget}`,
                    );
                }
            }
        });
    }

    return failures;
};

const verifyGeneratedApiLayout = async (): Promise<string[]> => {
    const failures: string[] = [];
    const generatedMarkdownFiles = await collectMarkdownFiles(apiReferenceRoot);
    const seenGeneratedApiPagePaths = new Set(
        generatedMarkdownFiles.map((file) =>
            path.relative(referenceRoot, file).replace(/\\/g, '/'),
        ),
    );

    for (const expectedPagePath of expectedGeneratedApiPagePaths) {
        if (!seenGeneratedApiPagePaths.has(expectedPagePath)) {
            failures.push(`missing generated page "${expectedPagePath}"`);
        }
    }

    for (const seenPagePath of seenGeneratedApiPagePaths) {
        if (!expectedGeneratedApiPagePaths.has(seenPagePath)) {
            failures.push(`unexpected generated page "${seenPagePath}"`);
        }
    }

    return failures;
};

const verifyApiEntryPages = async (): Promise<string[]> => {
    const failures: string[] = [];

    for (const relativePath of requiredApiEntryPages) {
        const absolutePath = path.resolve(repoRoot, relativePath);
        if (!(await fileExists(absolutePath))) {
            failures.push(relativePath);
        }
    }

    const navigationPath = path.resolve(repoRoot, apiNavigationPath);
    if (!(await fileExists(navigationPath))) {
        return failures;
    }

    const navigationJson = JSON.parse(
        await fs.readFile(navigationPath, 'utf8'),
    ) as {
        children?: unknown;
        title?: string;
        path?: string;
    }[];
    const seenNavigationPaths = new Set<string>();

    const visitNavigationItems = (
        items: readonly {
            children?: unknown;
            title?: string;
            path?: string;
        }[],
    ): void => {
        for (const item of items) {
            if (typeof item.path === 'string') {
                seenNavigationPaths.add(item.path);
            }

            if (Array.isArray(item.children)) {
                visitNavigationItems(
                    item.children as {
                        children?: unknown;
                        title?: string;
                        path?: string;
                    }[],
                );
            }
        }
    };

    visitNavigationItems(navigationJson);

    for (const [
        navigationPathValue,
        moduleName,
    ] of expectedGeneratedApiNavigationPaths) {
        if (!seenNavigationPaths.has(navigationPathValue)) {
            failures.push(`navigation.json missing module "${moduleName}"`);
        }
    }

    for (const seenNavigationPath of seenNavigationPaths) {
        if (!expectedGeneratedApiNavigationPaths.has(seenNavigationPath)) {
            failures.push(
                `navigation.json contains unexpected path "${seenNavigationPath}"`,
            );
        }
    }

    return failures;
};

const getReflectionSummary = (reflection: DeclarationReflection): string => {
    const comment =
        reflection.comment ??
        reflection.signatures?.find(
            (signature) => signature.comment !== undefined,
        )?.comment;

    return Comment.combineDisplayParts(comment?.summary).trim();
};

const publicReflectionKinds =
    ReflectionKind.Module |
    ReflectionKind.Class |
    ReflectionKind.Function |
    ReflectionKind.TypeAlias |
    ReflectionKind.Interface |
    ReflectionKind.Variable;

const loadTypeDocProject = async (): Promise<ProjectReflection> => {
    const app = await Application.bootstrapWithPlugins(config);
    const project = await app.convert();

    if (project === undefined) {
        throw new Error('TypeDoc could not build the public reflection graph');
    }

    return project;
};

const verifyTypeDocSummaries = (project: ProjectReflection): string[] => {
    const failures: string[] = [];
    const seen = new Set<string>();

    for (const reflection of project.getReflectionsByKind(
        publicReflectionKinds,
    )) {
        const publicReflection = reflection.isReference()
            ? reflection.getTargetReflectionDeep()
            : reflection;

        if (
            !publicReflection.kindOf(publicReflectionKinds) ||
            publicReflection.isProject()
        ) {
            continue;
        }

        const key = `${publicReflection.kind}:${publicReflection.getFullName()}`;
        if (seen.has(key)) {
            continue;
        }
        seen.add(key);

        const summary = getReflectionSummary(
            publicReflection as DeclarationReflection,
        );
        if (summary === '') {
            failures.push(publicReflection.getFullName());
        }
    }

    return failures.sort();
};

const verifyPublicSurfaceAllowlist = (project: ProjectReflection): string[] => {
    const allowedExports = new Set<string>([
        ...publicSurface.runtimeExports,
        ...publicSurface.publicTypeExports,
    ]);
    const seenExports = new Set<string>();
    const failures: string[] = [];

    for (const reflection of project.getReflectionsByKind(
        publicReflectionKinds,
    )) {
        const publicReflection = reflection.isReference()
            ? reflection.getTargetReflectionDeep()
            : reflection;

        if (
            !publicReflection.kindOf(publicReflectionKinds) ||
            publicReflection.isProject() ||
            publicReflection.kindOf(ReflectionKind.Module)
        ) {
            continue;
        }

        seenExports.add(publicReflection.name);
        if (!allowedExports.has(publicReflection.name)) {
            failures.push(`unexpected export "${publicReflection.name}"`);
        }
    }

    for (const expectedExport of allowedExports) {
        if (!seenExports.has(expectedExport)) {
            failures.push(`missing export "${expectedExport}"`);
        }
    }

    return failures.sort();
};

const main = async (): Promise<void> => {
    const linkFailures = await verifyLinks();
    const baseAwareFailures = await verifyBaseAwareLinks();
    const generatedLayoutFailures = await verifyGeneratedApiLayout();
    const apiFailures = await verifyApiEntryPages();
    const typeDocProject = await loadTypeDocProject();
    const summaryFailures = verifyTypeDocSummaries(typeDocProject);
    const surfaceFailures = verifyPublicSurfaceAllowlist(typeDocProject);

    const failures: string[] = [];

    if (linkFailures.length > 0) {
        failures.push('Broken relative links:');
        failures.push(...linkFailures.map((failure) => `- ${failure}`));
    }

    if (baseAwareFailures.length > 0) {
        failures.push('Base-unsafe internal docs links:');
        failures.push(...baseAwareFailures.map((failure) => `- ${failure}`));
    }

    if (generatedLayoutFailures.length > 0) {
        failures.push('Generated API layout violations:');
        failures.push(
            ...generatedLayoutFailures.map((failure) => `- ${failure}`),
        );
    }

    if (apiFailures.length > 0) {
        failures.push('Missing generated API entry pages:');
        failures.push(...apiFailures.map((failure) => `- ${failure}`));
    }

    if (summaryFailures.length > 0) {
        failures.push('Public API reflections without a summary:');
        failures.push(...summaryFailures.map((failure) => `- ${failure}`));
    }

    if (surfaceFailures.length > 0) {
        failures.push('Public API reflections outside the surface manifest:');
        failures.push(...surfaceFailures.map((failure) => `- ${failure}`));
    }

    if (failures.length > 0) {
        throw new Error(failures.join('\n'));
    }

    console.log('Documentation verification passed.');
};

void main();

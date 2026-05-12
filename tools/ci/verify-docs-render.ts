import { createReadStream } from 'node:fs';
import { stat } from 'node:fs/promises';
import { createServer, type ServerResponse } from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { chromium, type Page } from 'playwright';

const repoRoot = fileURLToPath(new URL('../../', import.meta.url));
const docsDistRoot = path.resolve(repoRoot, 'docs', 'dist');
const host = '127.0.0.1';
const routesToCheck = [
    '/',
    '/guides/getting-started/',
    '/spec/',
    '/api/',
    '/api/reference/sealed-lattice/',
] as const;
const viewportsToCheck = [
    { height: 844, name: 'mobile', width: 390 },
    { height: 900, name: 'tablet', width: 768 },
    { height: 900, name: 'desktop', width: 1280 },
] as const;

const contentTypes = new Map([
    ['.css', 'text/css; charset=utf-8'],
    ['.html', 'text/html; charset=utf-8'],
    ['.js', 'text/javascript; charset=utf-8'],
    ['.json', 'application/json; charset=utf-8'],
    ['.svg', 'image/svg+xml'],
    ['.wasm', 'application/wasm'],
    ['.woff', 'font/woff'],
    ['.woff2', 'font/woff2'],
]);

const sendNotFound = (response: ServerResponse): void => {
    response.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' });
    response.end('Not found');
};

const resolveRequestPath = async (requestUrl: string): Promise<string> => {
    const parsedUrl = new URL(requestUrl, 'http://localhost');
    const decodedPath = decodeURIComponent(parsedUrl.pathname);
    const candidatePath = decodedPath.endsWith('/')
        ? path.join(docsDistRoot, decodedPath, 'index.html')
        : path.join(docsDistRoot, decodedPath);
    const resolvedCandidatePath = path.resolve(candidatePath);
    const relativePath = path.relative(docsDistRoot, resolvedCandidatePath);

    if (relativePath.startsWith('..') || path.isAbsolute(relativePath)) {
        throw new Error(
            `Docs request escaped the output directory: ${decodedPath}`,
        );
    }

    try {
        const candidateStats = await stat(resolvedCandidatePath);
        if (candidateStats.isFile()) {
            return resolvedCandidatePath;
        }
    } catch {
        if (!path.extname(resolvedCandidatePath)) {
            const fallbackPath = path.join(resolvedCandidatePath, 'index.html');
            const fallbackStats = await stat(fallbackPath);
            if (fallbackStats.isFile()) {
                return fallbackPath;
            }
        }
    }

    throw new Error(`Docs route does not exist: ${decodedPath}`);
};

const startStaticServer = async (): Promise<{
    readonly close: () => Promise<void>;
    readonly origin: string;
}> => {
    const server = createServer((request, response) => {
        void (async (): Promise<void> => {
            try {
                const filePath = await resolveRequestPath(request.url ?? '/');
                const extension = path.extname(filePath);
                response.writeHead(200, {
                    'content-type':
                        contentTypes.get(extension) ??
                        'application/octet-stream',
                });
                createReadStream(filePath).pipe(response);
            } catch {
                sendNotFound(response);
            }
        })();
    });

    await new Promise<void>((resolve, reject) => {
        server.once('error', reject);
        server.listen(0, host, () => {
            server.off('error', reject);
            resolve();
        });
    });

    const address = server.address();
    if (address === null || typeof address === 'string') {
        throw new Error('Docs static server did not bind to a TCP port.');
    }

    return {
        close: () =>
            new Promise<void>((resolve, reject) => {
                server.close((error) => {
                    if (error === undefined) {
                        resolve();
                    } else {
                        reject(error);
                    }
                });
            }),
        origin: `http://${host}:${address.port}`,
    };
};

const requireVisibleElement = async (
    page: Page,
    selector: string,
    route: string,
): Promise<void> => {
    const element = page.locator(selector).first();
    if ((await element.count()) === 0 || !(await element.isVisible())) {
        throw new Error(`${route} is missing visible selector ${selector}`);
    }
};

const verifyThemeToggle = async (
    page: Page,
    route: string,
    requireVisibleToggle: boolean,
    exerciseToggle: boolean,
): Promise<void> => {
    const toggle = page.locator('[data-sl-theme-toggle]').first();
    if ((await toggle.count()) === 0) {
        throw new Error(`${route} is missing the theme toggle`);
    }
    if (!(await toggle.isVisible())) {
        if (requireVisibleToggle) {
            throw new Error(`${route} theme toggle is hidden on desktop`);
        }
        return;
    }

    const ariaLabel = await toggle.getAttribute('aria-label');
    if (
        ariaLabel !== 'Switch to dark theme' &&
        ariaLabel !== 'Switch to light theme'
    ) {
        throw new Error(
            `${route} theme toggle has an invalid accessible label`,
        );
    }
    if (!exerciseToggle) {
        return;
    }

    const initialTheme = await page.evaluate(
        () => document.documentElement.dataset.theme ?? '',
    );
    await toggle.click();
    const toggledTheme = await page.evaluate(
        () => document.documentElement.dataset.theme ?? '',
    );

    if (initialTheme === toggledTheme) {
        throw new Error(`${route} theme toggle did not change the theme`);
    }
};

const verifyDesktopRails = async (page: Page, route: string): Promise<void> => {
    const overlap = await page.evaluate(() => {
        const mainPane = document.querySelector('.main-pane');
        const sidebarPane = document.querySelector('.sidebar-pane');
        const rightSidebar = document.querySelector('.right-sidebar');

        if (
            !(mainPane instanceof HTMLElement) ||
            !(sidebarPane instanceof HTMLElement) ||
            !(rightSidebar instanceof HTMLElement)
        ) {
            return undefined;
        }

        const mainBox = mainPane.getBoundingClientRect();
        const sidebarBox = sidebarPane.getBoundingClientRect();
        const rightBox = rightSidebar.getBoundingClientRect();

        return {
            leftRailOverlapsMain: sidebarBox.right > mainBox.left + 1,
            mainOverlapsRightRail: mainBox.right > rightBox.left + 1,
        };
    });

    if (overlap === undefined) {
        return;
    }
    if (overlap.leftRailOverlapsMain || overlap.mainOverlapsRightRail) {
        throw new Error(`${route} desktop docs rails overlap the main content`);
    }
};

const verifyRoute = async (
    page: Page,
    origin: string,
    route: string,
    viewportName: string,
): Promise<void> => {
    const consoleErrors: string[] = [];
    const pageErrors: string[] = [];
    page.on('console', (message) => {
        if (message.type() === 'error') {
            consoleErrors.push(message.text());
        }
    });
    page.on('pageerror', (error) => {
        pageErrors.push(error.message);
    });

    const response = await page.goto(`${origin}${route}`, {
        waitUntil: 'networkidle',
    });
    if (!response?.ok()) {
        throw new Error(
            `${route} returned ${response?.status() ?? 'no response'}`,
        );
    }

    await requireVisibleElement(page, 'main', route);
    await requireVisibleElement(page, 'a[href]', route);
    await verifyThemeToggle(
        page,
        route,
        viewportName === 'desktop',
        viewportName === 'desktop' && route === '/',
    );

    if (viewportName === 'desktop') {
        await verifyDesktopRails(page, route);
    }
    if (consoleErrors.length > 0 || pageErrors.length > 0) {
        throw new Error(
            `${route} emitted browser errors:\n${[
                ...consoleErrors,
                ...pageErrors,
            ].join('\n')}`,
        );
    }
};

const main = async (): Promise<void> => {
    await stat(path.join(docsDistRoot, 'index.html'));
    const server = await startStaticServer();
    const browser = await chromium.launch();

    try {
        for (const viewport of viewportsToCheck) {
            const page = await browser.newPage({
                viewport: {
                    height: viewport.height,
                    width: viewport.width,
                },
            });
            try {
                for (const route of routesToCheck) {
                    await verifyRoute(
                        page,
                        server.origin,
                        route,
                        viewport.name,
                    );
                }
            } finally {
                await page.close();
            }
        }
    } finally {
        await browser.close();
        await server.close();
    }

    console.log('Rendered docs smoke verification passed.');
};

void main();

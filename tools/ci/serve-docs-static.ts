import { createReadStream } from 'node:fs';
import { stat } from 'node:fs/promises';
import { createServer, type ServerResponse } from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = fileURLToPath(new URL('../../', import.meta.url));
const docsDistRoot = path.resolve(repoRoot, 'docs', 'dist');
const host = '127.0.0.1';
const docsBasePath =
    process.env.GITHUB_ACTIONS === 'true' ? '/sealed-lattice' : '/';
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

const argumentValue = (name: string): string | null => {
    const argumentIndex = process.argv.indexOf(name);
    if (argumentIndex < 0) {
        return null;
    }
    const value = process.argv[argumentIndex + 1];
    if (value === undefined || value.startsWith('--')) {
        throw new Error(`Missing value for ${name}.`);
    }

    return value;
};

const requestedPort = (): number => {
    const portText = argumentValue('--port');
    if (portText === null) {
        return 0;
    }

    const port = Number(portText);
    if (!Number.isInteger(port) || port <= 0 || port > 65_535) {
        throw new Error(`Invalid docs static server port: ${portText}`);
    }

    return port;
};

const stripDocsBasePath = (decodedPath: string): string => {
    if (docsBasePath === '/') {
        return decodedPath;
    }
    if (decodedPath === docsBasePath) {
        return '/';
    }
    if (decodedPath.startsWith(`${docsBasePath}/`)) {
        return decodedPath.slice(docsBasePath.length);
    }

    return decodedPath;
};

const resolveRequestPath = async (requestUrl: string): Promise<string> => {
    const parsedUrl = new URL(requestUrl, 'http://localhost');
    const decodedPath = decodeURIComponent(parsedUrl.pathname);
    const requestPath = stripDocsBasePath(decodedPath);
    const relativeRequestPath = requestPath.replace(/^\/+/u, '');
    const candidatePath = requestPath.endsWith('/')
        ? path.join(docsDistRoot, relativeRequestPath, 'index.html')
        : path.join(docsDistRoot, relativeRequestPath);
    const resolvedCandidatePath = path.resolve(candidatePath);
    const relativePath = path.relative(docsDistRoot, resolvedCandidatePath);

    if (relativePath.startsWith('..') || path.isAbsolute(relativePath)) {
        throw new Error(
            `Docs request escaped the output directory: ${requestPath}`,
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

    throw new Error(`Docs route does not exist: ${requestPath}`);
};

const sendNotFound = (response: ServerResponse): void => {
    response.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' });
    response.end('Not found');
};

const server = createServer((request, response) => {
    void (async (): Promise<void> => {
        try {
            const filePath = await resolveRequestPath(request.url ?? '/');
            const extension = path.extname(filePath);
            response.writeHead(200, {
                'content-type':
                    contentTypes.get(extension) ?? 'application/octet-stream',
            });
            createReadStream(filePath).pipe(response);
        } catch {
            sendNotFound(response);
        }
    })();
});

server.listen(requestedPort(), host, () => {
    const address = server.address();
    if (address === null || typeof address === 'string') {
        throw new Error('Docs static server did not bind to a TCP port.');
    }
    console.log(
        `Docs static server listening at http://${host}:${address.port}`,
    );
});

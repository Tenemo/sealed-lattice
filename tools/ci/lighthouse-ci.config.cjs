const { chromium } = require("playwright");

const docsBasePath =
    process.env.GITHUB_ACTIONS === "true" ? "/sealed-lattice" : "";
const docsRoute = (route) => `${docsBasePath}${route}`;

module.exports = {
    ci: {
        collect: {
            chromePath: chromium.executablePath(),
            numberOfRuns: 1,
            puppeteerLaunchOptions: {
                args: ["--no-sandbox"],
            },
            puppeteerScript: "./tools/ci/lighthouse-ci-puppeteer.cjs",
            settings: {
                hostname: "0.0.0.0",
                onlyCategories: ["accessibility", "best-practices"],
            },
            startServerCommand:
                "pnpm exec tsx ./tools/ci/serve-docs-static.ts --port 43731",
            startServerReadyPattern: "Docs static server listening",
            url: [
                docsRoute("/"),
                docsRoute("/guides/getting-started/"),
                docsRoute("/spec/"),
                docsRoute("/api/"),
                docsRoute("/api/reference/sealed-lattice/"),
            ].map((route) => `http://127.0.0.1:43731${route}`),
        },
        assert: {
            assertions: {
                "categories:accessibility": ["error", { minScore: 0.9 }],
                "categories:best-practices": ["error", { minScore: 0.9 }],
                "errors-in-console": "error",
                "is-crawlable": "off",
            },
        },
        upload: {
            target: "filesystem",
            outputDir: "./temp/lighthouse-ci",
        },
    },
};

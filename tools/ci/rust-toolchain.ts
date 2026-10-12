import path from 'node:path';

// The Rust toolchain every cargo and rustc command selects, the one the
// protocol workspace's rust-toolchain.toml names, and its compiler's commit.
export const rustToolchain = '+1.95.0';
export const rustCompilerCommit = '59807616e1fa2540724bfbac14d7976d7e4a3860';

// The environment of a cargo command in the protocol workspace: its shared
// target directory, without incremental artifacts or ambient compiler flags,
// so the lanes that share the directory reuse each other's artifacts.
export const workspaceCargoEnvironment = (
    workspace: string,
    inherited: NodeJS.ProcessEnv = process.env,
): NodeJS.ProcessEnv => ({
    ...inherited,
    CARGO_INCREMENTAL: '0',
    CARGO_TARGET_DIR: path.join(workspace, 'target'),
    RUSTFLAGS: '',
    CARGO_ENCODED_RUSTFLAGS: '',
});

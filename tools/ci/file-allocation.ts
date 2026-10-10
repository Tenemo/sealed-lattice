import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { lstat, readdir } from 'node:fs/promises';
import path from 'node:path';
import { promisify } from 'node:util';

export type FileAllocation = Readonly<{
    files: number;
    fileBytes: number;
    allocatedBytes: number;
    indexedDatabaseFileBytes: number;
    indexedDatabaseAllocatedBytes: number;
    missingEntries: number;
    unreadableEntries: number;
    skippedLinks: number;
    multiplyLinkedFiles: number;
}>;

const empty = (): FileAllocation => ({
    files: 0,
    fileBytes: 0,
    allocatedBytes: 0,
    indexedDatabaseFileBytes: 0,
    indexedDatabaseAllocatedBytes: 0,
    missingEntries: 0,
    unreadableEntries: 0,
    skippedLinks: 0,
    multiplyLinkedFiles: 0,
});

// FILE_STANDARD_INFO reports AllocationSize separately from EndOfFile.
// https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_standard_info
// The sums cover default file streams, not volume metadata or the filesystem
// journal. Hard-linked files are counted by path and reported separately.
const windowsReader = String.raw`
$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public class TaskFileAllocation {
    public long files, fileBytes, allocatedBytes, indexedDatabaseFileBytes, indexedDatabaseAllocatedBytes;
    public long missingEntries, unreadableEntries, skippedLinks, multiplyLinkedFiles;
    [StructLayout(LayoutKind.Sequential)]
    struct StandardInfo {
        public long AllocationSize, EndOfFile;
        public uint NumberOfLinks;
        public byte DeletePending, Directory;
    }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern SafeFileHandle CreateFileW(string name, uint access, uint sharing, IntPtr security, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetFileInformationByHandleEx(SafeFileHandle handle, int kind, out StandardInfo info, uint size);
    void Error(int code) {
        if (code == 2 || code == 3) missingEntries++;
        else unreadableEntries++;
    }
    void Visit(FileSystemInfo entry, bool indexedDatabase) {
        try {
            FileAttributes attributes = File.GetAttributes(entry.FullName);
            if ((attributes & FileAttributes.ReparsePoint) != 0) { skippedLinks++; return; }
            if ((attributes & FileAttributes.Directory) != 0) {
                indexedDatabase = indexedDatabase || entry.Name == "IndexedDB";
                foreach (FileSystemInfo child in ((DirectoryInfo)entry).EnumerateFileSystemInfos()) Visit(child, indexedDatabase);
                return;
            }
            using (SafeFileHandle handle = CreateFileW(entry.FullName, 0x80, 7, IntPtr.Zero, 3, 0, IntPtr.Zero)) {
                if (handle.IsInvalid) { Error(Marshal.GetLastWin32Error()); return; }
                StandardInfo info;
                if (!GetFileInformationByHandleEx(handle, 1, out info, (uint)Marshal.SizeOf(typeof(StandardInfo)))) { Error(Marshal.GetLastWin32Error()); return; }
                files++;
                fileBytes += info.EndOfFile;
                allocatedBytes += info.AllocationSize;
                if (info.NumberOfLinks > 1) multiplyLinkedFiles++;
                if (indexedDatabase) {
                    indexedDatabaseFileBytes += info.EndOfFile;
                    indexedDatabaseAllocatedBytes += info.AllocationSize;
                }
            }
        } catch (FileNotFoundException) { missingEntries++; }
          catch (DirectoryNotFoundException) { missingEntries++; }
          catch (UnauthorizedAccessException) { unreadableEntries++; }
          catch (IOException) { unreadableEntries++; }
    }
    public static TaskFileAllocation Read(string root) {
        TaskFileAllocation result = new TaskFileAllocation();
        result.Visit(new DirectoryInfo(root), false);
        return result;
    }
}
'@
`;

export const sampleFileAllocation = async (
    directories: readonly string[],
): Promise<readonly FileAllocation[]> => {
    if (directories.length === 0) return [];
    if (process.platform === 'win32') {
        const encodedPaths = Buffer.from(
            JSON.stringify(
                directories.map((directory) => path.resolve(directory)),
            ),
        ).toString('base64');
        const script =
            windowsReader +
            String.raw`
$taskPaths = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String([Console]::In.ReadToEnd())) | ConvertFrom-Json
$taskSizes = @($taskPaths | ForEach-Object { [TaskFileAllocation]::Read($_) })
ConvertTo-Json -Compress -InputObject $taskSizes
`;
        const running = promisify(execFile)(
            'powershell.exe',
            [
                '-NoProfile',
                '-NonInteractive',
                '-EncodedCommand',
                Buffer.from(script, 'utf16le').toString('base64'),
            ],
            { windowsHide: true, timeout: 30_000, maxBuffer: 2 ** 20 },
        );
        running.child.stdin!.end(encodedPaths);
        const result = await running;
        const values: unknown = JSON.parse(result.stdout);
        assert.ok(
            Array.isArray(values) && values.length === directories.length,
        );
        for (const value of values as unknown[]) {
            assert.ok(value !== null && typeof value === 'object');
            assert.deepEqual(
                Object.keys(value).sort(),
                Object.keys(empty()).sort(),
            );
            assert.ok(
                Object.values(value).every(
                    (count) =>
                        typeof count === 'number' &&
                        Number.isSafeInteger(count) &&
                        count >= 0,
                ),
            );
        }
        return values as FileAllocation[];
    }
    return Promise.all(
        directories.map(async (directory) => {
            const result = { ...empty() };
            const visit = async (
                file: string,
                indexedDatabase: boolean,
            ): Promise<void> => {
                try {
                    const details = await lstat(file);
                    if (details.isSymbolicLink()) {
                        result.skippedLinks++;
                        return;
                    }
                    if (details.isDirectory()) {
                        for (const name of await readdir(file))
                            await visit(
                                path.join(file, name),
                                indexedDatabase || name === 'IndexedDB',
                            );
                        return;
                    }
                    if (!details.isFile()) {
                        result.unreadableEntries++;
                        return;
                    }
                    assert.ok(
                        Number.isSafeInteger(details.blocks) &&
                            details.blocks >= 0,
                    );
                    const allocated = details.blocks * 512;
                    result.files++;
                    result.fileBytes += details.size;
                    result.allocatedBytes += allocated;
                    if (details.nlink > 1) result.multiplyLinkedFiles++;
                    if (indexedDatabase) {
                        result.indexedDatabaseFileBytes += details.size;
                        result.indexedDatabaseAllocatedBytes += allocated;
                    }
                } catch (error) {
                    if (
                        error !== null &&
                        typeof error === 'object' &&
                        'code' in error &&
                        (error.code === 'ENOENT' || error.code === 'ENOTDIR')
                    )
                        result.missingEntries++;
                    else if (
                        error !== null &&
                        typeof error === 'object' &&
                        'code' in error &&
                        (error.code === 'EACCES' || error.code === 'EPERM')
                    )
                        result.unreadableEntries++;
                    else throw error;
                }
            };
            await visit(directory, path.basename(directory) === 'IndexedDB');
            return result;
        }),
    );
};

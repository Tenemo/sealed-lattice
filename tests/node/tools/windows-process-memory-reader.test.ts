import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';

import { describe, expect, it } from 'vitest';

import { createWindowsProcessMemoryReader } from '#tools/ci/windows-process-memory-reader.js';

// Portable subprocess-protocol controls. Actual Windows counters and process
// identity are exercised by the separate native Chrome measurement fixture.
const fixture = (response: string, timeoutMilliseconds = 5_000) => {
    let child: ChildProcessWithoutNullStreams | undefined;
    const reader = createWindowsProcessMemoryReader({
        timeoutMilliseconds,
        launch: () => {
            child = spawn(
                process.execPath,
                [
                    '-e',
                    `
                const lines=require('node:readline').createInterface({input:process.stdin});
                lines.on('line',line=>{const request=JSON.parse(line);${response}});
            `,
                ],
                { windowsHide: true, stdio: 'pipe' },
            );
            return child;
        },
    });
    const closed = () =>
        new Promise<void>((resolve) => {
            if (!child || child.exitCode !== null || child.signalCode !== null)
                resolve();
            else child.once('close', () => resolve());
        });
    return { reader, closed };
};
const valid = String.raw`const value=JSON.stringify({id:request.id,rows:request.identifiers.map(Id=>({Id,ProcessName:'chrome',Started:'100',PrivateMemorySize64:request.id,PeakPagedMemorySize64:10}))})+'\n';process.stdout.write(value.slice(0,5));setTimeout(()=>process.stdout.write(value.slice(5)),5);`;

describe('persistent Windows counter transport', () => {
    it('correlates fresh split responses and closes its owned helper', async () => {
        const { reader, closed } = fixture(valid);
        try {
            const first = await reader.read([12, 19]);
            const second = await reader.read([19]);
            expect(first.map((row) => row.Id)).toEqual([12, 19]);
            expect(second[0].PrivateMemorySize64).toBe(2);
            expect(first[0].PrivateMemorySize64).toBe(1);
        } finally {
            reader.close();
            await closed();
        }
        await expect(reader.read([19])).rejects.toThrow('closed');
    });

    it('refuses concurrent and invalid requests without replacing an active sample', async () => {
        const { reader, closed } = fixture(valid);
        try {
            await expect(reader.read([])).rejects.toThrow('Invalid');
            await expect(reader.read([-1])).rejects.toThrow('Invalid');
            const first = reader.read([1]);
            await expect(reader.read([2])).rejects.toThrow('Concurrent');
            expect((await first)[0].Id).toBe(1);
        } finally {
            reader.close();
            await closed();
        }
    });

    it('poisons mismatched and malformed replies instead of reusing old measurements', async () => {
        for (const response of [
            "process.stdout.write(JSON.stringify({id:request.id+1,rows:[]})+'\\n');",
            "process.stdout.write(JSON.stringify({id:request.id,rows:[{Id:1,ProcessName:'chrome',Started:'100',PrivateMemorySize64:5,PeakPagedMemorySize64:4}]})+'\\n');",
            "process.stdout.write(JSON.stringify({id:request.id,rows:[{Id:1,ProcessName:null,Started:'100',PrivateMemorySize64:5,PeakPagedMemorySize64:5}]})+'\\n');",
            "process.stdout.write(JSON.stringify({id:request.id,rows:[{Id:1,ProcessName:'chrome',Started:null,PrivateMemorySize64:5,PeakPagedMemorySize64:5}]})+'\\n');",
            "process.stdout.write(JSON.stringify({id:request.id,rows:[{Id:1,ProcessName:'chrome',Started:'100',PrivateMemorySize64:null,PeakPagedMemorySize64:5}]})+'\\n');",
            "process.stdout.write(JSON.stringify({id:request.id,error:'AccessDenied'})+'\\n');",
        ]) {
            const { reader, closed } = fixture(response);
            try {
                await expect(reader.read([1])).rejects.toThrow();
                await expect(reader.read([1])).rejects.toThrow();
            } finally {
                reader.close();
                await closed();
            }
        }
    });

    it('fails a missed deadline once and terminates the helper', async () => {
        const { reader, closed } = fixture('setTimeout(()=>{},10000);', 100);
        try {
            await expect(reader.read([1])).rejects.toThrow('deadline');
            await expect(reader.read([1])).rejects.toThrow('deadline');
            await closed();
        } finally {
            reader.close();
        }
    });

    it('fails on helper exit while a request is pending', async () => {
        const { reader, closed } = fixture('process.exit(2);');
        try {
            await expect(reader.read([1])).rejects.toThrow('exited');
        } finally {
            reader.close();
            await closed();
        }
    });

    it('closes an in-flight request without retrying or retaining exit listeners', async () => {
        const initialListeners = process.listenerCount('exit');
        for (let lifetime = 0; lifetime < 3; lifetime++) {
            const { reader, closed } = fixture('setTimeout(()=>{},10000);');
            const pending = reader.read([1]);
            const rejected = pending.catch((error: unknown) => error);
            reader.close();
            reader.close();
            expect(await rejected).toMatchObject({
                message: 'Process memory reader closed.',
            });
            await closed();
            await expect(reader.read([1])).rejects.toThrow('closed');
            expect(process.listenerCount('exit')).toBe(initialListeners);
        }
    });
});

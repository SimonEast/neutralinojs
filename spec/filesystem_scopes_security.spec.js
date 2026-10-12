const assert = require('assert');
const http = require('http');
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

describe('Filesystem scopes security & boundary enforcement (CWE-22 / GHSA-88px-53w7-3ppp)', () => {
    const binPath = path.resolve(__dirname, '../bin/neutralino-' +
        (process.platform === 'darwin' ? 'mac_' + process.arch :
         process.platform === 'linux' ? 'linux_' + process.arch : 'win_x64.exe'));
    const tmpAuthPath = path.resolve(__dirname, '../bin/.tmp/auth_info.json');
    const customConfigPath = path.resolve(__dirname, '../bin/.tmp/test_fs_scopes.json');

    function makeWsFrame(payloadStr) {
        const payloadBuf = Buffer.from(payloadStr, 'utf8');
        const len = payloadBuf.length;
        let header;
        if (len < 126) {
            header = Buffer.from([0x81, 0x80 | len, 0x00, 0x00, 0x00, 0x00]);
        } else {
            header = Buffer.from([0x81, 0x80 | 126, (len >> 8) & 0xff, len & 0xff, 0x00, 0x00, 0x00, 0x00]);
        }
        return Buffer.concat([header, payloadBuf]);
    }

    function sendNativeMessage(port, connectToken, token, method, data = {}) {
        return new Promise((resolve, reject) => {
            const req = http.request({
                port: port,
                host: '127.0.0.1',
                path: `/?connectToken=${connectToken}`,
                headers: {
                    'Connection': 'Upgrade',
                    'Upgrade': 'websocket',
                    'Sec-WebSocket-Version': '13',
                    'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ=='
                }
            });
            req.on('upgrade', (res, socket, head) => {
                let buffer = Buffer.alloc(0);
                const reqId = 'req-' + Math.random().toString(36).slice(2);

                socket.on('data', (chunk) => {
                    buffer = Buffer.concat([buffer, chunk]);
                    while (buffer.length >= 2) {
                        let offset = 2;
                        let len = buffer[1] & 0x7f;
                        if (len === 126) {
                            if (buffer.length < 4) break;
                            len = (buffer[2] << 8) | buffer[3];
                            offset = 4;
                        } else if (len === 127) {
                            break;
                        }
                        if (buffer.length < offset + len) break;
                        const payload = buffer.subarray(offset, offset + len).toString('utf8');
                        buffer = buffer.subarray(offset + len);
                        try {
                            const parsed = JSON.parse(payload);
                            if (parsed.id === reqId) {
                                socket.destroy();
                                return resolve(parsed);
                            }
                        } catch (e) {}
                    }
                });

                const msg = JSON.stringify({
                    id: reqId,
                    method: method,
                    accessToken: token,
                    data: data
                });
                socket.write(makeWsFrame(msg));
            });
            req.on('error', reject);
            req.end();
        });
    }

    async function waitForAuthInfo() {
        for (let i = 0; i < 40; i++) {
            await new Promise(r => setTimeout(r, 100));
            if (fs.existsSync(tmpAuthPath)) {
                try {
                    const raw = fs.readFileSync(tmpAuthPath, 'utf8');
                    const info = JSON.parse(raw);
                    if (info.nlPort && info.nlConnectToken && info.nlToken) {
                        return info;
                    }
                } catch (e) {}
            }
        }
        throw new Error('Timed out waiting for auth_info.json');
    }

    beforeEach(() => {
        try {
            if (fs.existsSync(tmpAuthPath)) fs.unlinkSync(tmpAuthPath);
        } catch (e) {}
    });

    afterEach(() => {
        try {
            if (fs.existsSync(customConfigPath)) fs.unlinkSync(customConfigPath);
        } catch (e) {}
    });

    it('logs a security warning when filesystem.* is allowed but filesystemScopes is omitted', async function() {
        this.timeout(10000);
        const baseConfig = JSON.parse(fs.readFileSync(path.resolve(__dirname, '../bin/neutralino.config.json'), 'utf8'));
        baseConfig.defaultMode = 'cloud';
        baseConfig.nativeAllowList = ['app.*', 'filesystem.*'];
        delete baseConfig.filesystemScopes;
        if (baseConfig.modes?.cloud) {
            delete baseConfig.modes.cloud.nativeAllowList;
            delete baseConfig.modes.cloud.filesystemScopes;
        }
        fs.writeFileSync(customConfigPath, JSON.stringify(baseConfig, null, 2));

        let capturedLogs = '';
        const child = spawn(binPath, ['--load-dir-res', '--config-file=/.tmp/test_fs_scopes.json', '--export-auth-info', '--window-enable-inspector=false'], {
            cwd: path.resolve(__dirname, '../bin')
        });

        child.stdout.on('data', d => { capturedLogs += d.toString(); });
        child.stderr.on('data', d => { capturedLogs += d.toString(); });

        try {
            await waitForAuthInfo();
            assert.ok(capturedLogs.includes('SECURITY WARNING') && capturedLogs.includes('filesystemScopes'),
                'Must log a security warning when filesystemScopes is omitted');
        } finally {
            child.kill();
        }
    });

    it('supports backward-compatible nested filesystem.scopes configuration format', async function() {
        this.timeout(10000);
        const baseConfig = JSON.parse(fs.readFileSync(path.resolve(__dirname, '../bin/neutralino.config.json'), 'utf8'));
        baseConfig.defaultMode = 'cloud';
        delete baseConfig.filesystemScopes;
        baseConfig.filesystem = {
            scopes: {
                '${NL_PATH}/.tmp': 'read-write'
            }
        };
        if (baseConfig.modes?.cloud) {
            delete baseConfig.modes.cloud.nativeAllowList;
            delete baseConfig.modes.cloud.filesystemScopes;
        }
        fs.writeFileSync(customConfigPath, JSON.stringify(baseConfig, null, 2));

        const child = spawn(binPath, ['--load-dir-res', '--config-file=/.tmp/test_fs_scopes.json', '--export-auth-info', '--window-enable-inspector=false'], {
            cwd: path.resolve(__dirname, '../bin')
        });

        try {
            const authInfo = await waitForAuthInfo();

            // 1. Path inside nested scope (${NL_PATH}/.tmp/nested_test.txt) -> allowed
            const insideRes = await sendNativeMessage(authInfo.nlPort, authInfo.nlConnectToken, authInfo.nlToken, 'filesystem.writeFile', {
                path: path.resolve(__dirname, '../bin/.tmp/nested_test.txt'),
                data: 'hello'
            });
            assert.strictEqual(insideRes.data?.error, undefined, 'Write inside nested scope must succeed');

            // 2. Path outside nested scope (/tmp/outside_test.txt) -> blocked with NE_FS_SCOPERR
            const outsideRes = await sendNativeMessage(authInfo.nlPort, authInfo.nlConnectToken, authInfo.nlToken, 'filesystem.writeFile', {
                path: '/tmp/outside_test.txt',
                data: 'evil'
            });
            assert.ok(outsideRes.data?.error, 'Write outside nested scope must fail');
            assert.strictEqual(outsideRes.data.error.code, 'NE_FS_SCOPERR', 'Must fail with NE_FS_SCOPERR');
        } finally {
            child.kill();
        }
    });

    it('correctly handles root directory scope "/" without breaking child paths', async function() {
        this.timeout(10000);
        const baseConfig = JSON.parse(fs.readFileSync(path.resolve(__dirname, '../bin/neutralino.config.json'), 'utf8'));
        baseConfig.defaultMode = 'cloud';
        baseConfig.filesystemScopes = {
            '/': 'read-write'
        };
        if (baseConfig.modes?.cloud) {
            delete baseConfig.modes.cloud.nativeAllowList;
            delete baseConfig.modes.cloud.filesystemScopes;
        }
        fs.writeFileSync(customConfigPath, JSON.stringify(baseConfig, null, 2));

        const child = spawn(binPath, ['--load-dir-res', '--config-file=/.tmp/test_fs_scopes.json', '--export-auth-info', '--window-enable-inspector=false'], {
            cwd: path.resolve(__dirname, '../bin')
        });

        try {
            const authInfo = await waitForAuthInfo();

            // When scope is "/", an absolute path like /tmp/root_scope_test.txt must be allowed
            const testFilePath = '/tmp/neu_root_scope_test.txt';
            const writeRes = await sendNativeMessage(authInfo.nlPort, authInfo.nlConnectToken, authInfo.nlToken, 'filesystem.writeFile', {
                path: testFilePath,
                data: 'root_ok'
            });
            assert.strictEqual(writeRes.data?.error, undefined, 'Root scope "/" must allow paths starting with "/"');

            try { fs.unlinkSync(testFilePath); } catch (e) {}
        } finally {
            child.kill();
        }
    });
});

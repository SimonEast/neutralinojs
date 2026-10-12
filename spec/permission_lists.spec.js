const assert = require('assert');
const http = require('http');
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

describe('nativeAllowList and nativeBlockList precedence & intersection (CWE-284 / GHSA-7h48-j4q4-qwf3)', () => {
    const binPath = path.resolve(__dirname, '../bin/neutralino-' +
        (process.platform === 'darwin' ? 'mac_' + process.arch :
         process.platform === 'linux' ? 'linux_' + process.arch : 'win_x64.exe'));
    const tmpAuthPath = path.resolve(__dirname, '../bin/.tmp/auth_info.json');
    const customConfigPath = path.resolve(__dirname, '../bin/.tmp/test_both_lists.json');

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

    it('enforces nativeAllowList even when nativeBlockList is [] (empty array in root config)', async function() {
        this.timeout(10000);
        // Default neutralino.config.json sets root nativeBlockList: []
        // and modes.cloud.nativeAllowList: ["app.*", "storage.*"]
        const child = spawn(binPath, ['--load-dir-res', '--mode=cloud', '--export-auth-info', '--window-enable-inspector=false'], {
            cwd: path.resolve(__dirname, '../bin')
        });

        try {
            const authInfo = await waitForAuthInfo();

            // 1. Allowed method on allowlist (app.*)
            const appRes = await sendNativeMessage(authInfo.nlPort, authInfo.nlConnectToken, authInfo.nlToken, 'app.getConfig');
            assert.strictEqual(appRes.data?.error, undefined, 'app.getConfig should be allowed by nativeAllowList');

            // 2. Unlisted method not on allowlist (filesystem.*)
            const fsRes = await sendNativeMessage(authInfo.nlPort, authInfo.nlConnectToken, authInfo.nlToken, 'filesystem.readDirectory', { path: '.' });
            assert.ok(fsRes.data?.error, 'filesystem.readDirectory must be blocked when not on nativeAllowList');
            assert.strictEqual(fsRes.data.error.code, 'NE_RT_NATPRME', 'Error must be NE_RT_NATPRME');

            // 3. Unlisted method not on allowlist (os.*)
            const osRes = await sendNativeMessage(authInfo.nlPort, authInfo.nlConnectToken, authInfo.nlToken, 'os.getEnv', { key: 'PATH' });
            assert.ok(osRes.data?.error, 'os.getEnv must be blocked when not on nativeAllowList');
            assert.strictEqual(osRes.data.error.code, 'NE_RT_NATPRME', 'Error must be NE_RT_NATPRME');
        } finally {
            child.kill();
        }
    });

    it('enforces intersection when both nativeAllowList and nativeBlockList are non-empty', async function() {
        this.timeout(10000);
        const baseConfig = JSON.parse(fs.readFileSync(path.resolve(__dirname, '../bin/neutralino.config.json'), 'utf8'));
        baseConfig.defaultMode = 'cloud';
        baseConfig.nativeAllowList = ['app.*', 'os.*'];
        baseConfig.nativeBlockList = ['os.getEnv'];
        if (baseConfig.modes?.cloud) {
            delete baseConfig.modes.cloud.nativeAllowList;
            delete baseConfig.modes.cloud.nativeBlockList;
        }
        fs.writeFileSync(customConfigPath, JSON.stringify(baseConfig, null, 2));

        const child = spawn(binPath, ['--load-dir-res', '--config-file=/.tmp/test_both_lists.json', '--export-auth-info', '--window-enable-inspector=false'], {
            cwd: path.resolve(__dirname, '../bin')
        });

        try {
            const authInfo = await waitForAuthInfo();

            // 1. Allowed on allowlist and not blocked (app.getConfig)
            const appRes = await sendNativeMessage(authInfo.nlPort, authInfo.nlConnectToken, authInfo.nlToken, 'app.getConfig');
            assert.strictEqual(appRes.data?.error, undefined, 'app.getConfig should be allowed');

            // 2. Allowed on allowlist and not blocked (os.getEnvs)
            const osEnvsRes = await sendNativeMessage(authInfo.nlPort, authInfo.nlConnectToken, authInfo.nlToken, 'os.getEnvs');
            assert.strictEqual(osEnvsRes.data?.error, undefined, 'os.getEnvs should be allowed');

            // 3. On allowlist BUT explicitly blocked by blocklist (os.getEnv) -> MUST BE BLOCKED
            const osEnvRes = await sendNativeMessage(authInfo.nlPort, authInfo.nlConnectToken, authInfo.nlToken, 'os.getEnv', { key: 'PATH' });
            assert.ok(osEnvRes.data?.error, 'os.getEnv must be blocked by nativeBlockList');
            assert.strictEqual(osEnvRes.data.error.code, 'NE_RT_NATPRME', 'Error must be NE_RT_NATPRME');

            // 4. Neither in blocklist nor allowlist (filesystem.readDirectory) -> MUST BE BLOCKED BY ALLOWLIST
            const fsRes = await sendNativeMessage(authInfo.nlPort, authInfo.nlConnectToken, authInfo.nlToken, 'filesystem.readDirectory', { path: '.' });
            assert.ok(fsRes.data?.error, 'filesystem.readDirectory must be blocked because it is not in nativeAllowList');
            assert.strictEqual(fsRes.data.error.code, 'NE_RT_NATPRME', 'Error must be NE_RT_NATPRME');
        } finally {
            child.kill();
        }
    });

    it('denies blocked methods and allows unblocked methods when only nativeBlockList is configured', async function() {
        this.timeout(10000);
        const baseConfig = JSON.parse(fs.readFileSync(path.resolve(__dirname, '../bin/neutralino.config.json'), 'utf8'));
        baseConfig.defaultMode = 'cloud';
        delete baseConfig.nativeAllowList;
        baseConfig.nativeBlockList = ['filesystem.*'];
        if (baseConfig.modes?.cloud) {
            delete baseConfig.modes.cloud.nativeAllowList;
            delete baseConfig.modes.cloud.nativeBlockList;
        }
        fs.writeFileSync(customConfigPath, JSON.stringify(baseConfig, null, 2));

        const child = spawn(binPath, ['--load-dir-res', '--config-file=/.tmp/test_both_lists.json', '--export-auth-info', '--window-enable-inspector=false'], {
            cwd: path.resolve(__dirname, '../bin')
        });

        try {
            const authInfo = await waitForAuthInfo();

            // 1. Blocked method (filesystem.readDirectory) -> MUST BE BLOCKED
            const fsRes = await sendNativeMessage(authInfo.nlPort, authInfo.nlConnectToken, authInfo.nlToken, 'filesystem.readDirectory', { path: '.' });
            assert.ok(fsRes.data?.error, 'filesystem.readDirectory must be blocked by nativeBlockList');
            assert.strictEqual(fsRes.data.error.code, 'NE_RT_NATPRME', 'Error must be NE_RT_NATPRME');

            // 2. Unblocked method (app.getConfig) -> MUST BE ALLOWED
            const appRes = await sendNativeMessage(authInfo.nlPort, authInfo.nlConnectToken, authInfo.nlToken, 'app.getConfig');
            assert.strictEqual(appRes.data?.error, undefined, 'app.getConfig should be allowed when not in nativeBlockList');
        } finally {
            child.kill();
        }
    });

    it('denies all methods when nativeAllowList is an empty array []', async function() {
        this.timeout(10000);
        const baseConfig = JSON.parse(fs.readFileSync(path.resolve(__dirname, '../bin/neutralino.config.json'), 'utf8'));
        baseConfig.defaultMode = 'cloud';
        baseConfig.nativeAllowList = [];
        delete baseConfig.nativeBlockList;
        if (baseConfig.modes?.cloud) {
            delete baseConfig.modes.cloud.nativeAllowList;
            delete baseConfig.modes.cloud.nativeBlockList;
        }
        fs.writeFileSync(customConfigPath, JSON.stringify(baseConfig, null, 2));

        const child = spawn(binPath, ['--load-dir-res', '--config-file=/.tmp/test_both_lists.json', '--export-auth-info', '--window-enable-inspector=false'], {
            cwd: path.resolve(__dirname, '../bin')
        });

        try {
            const authInfo = await waitForAuthInfo();

            // app.getConfig should be blocked when nativeAllowList is empty
            const appRes = await sendNativeMessage(authInfo.nlPort, authInfo.nlConnectToken, authInfo.nlToken, 'app.getConfig');
            assert.ok(appRes.data?.error, 'app.getConfig must be blocked when nativeAllowList is empty');
            assert.strictEqual(appRes.data.error.code, 'NE_RT_NATPRME', 'Error must be NE_RT_NATPRME');
        } finally {
            child.kill();
        }
    });
});

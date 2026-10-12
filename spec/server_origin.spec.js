const assert = require('assert');
const http = require('http');
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

describe('WebSocket Origin header validation (CWE-346 / GHSA-rjgv-ffxc-h5c2)', () => {
    const binPath = path.resolve(__dirname, '../bin/neutralino-' +
        (process.platform === 'darwin' ? 'mac_' + process.arch :
         process.platform === 'linux' ? 'linux_' + process.arch : 'win_x64.exe'));
    const tmpAuthPath = path.resolve(__dirname, '../bin/.tmp/auth_info.json');

    function testWsUpgrade(port, connectToken, headers = {}) {
        return new Promise((resolve, reject) => {
            const req = http.request({
                port: port,
                host: '127.0.0.1',
                path: `/?connectToken=${connectToken}`,
                headers: {
                    'Connection': 'Upgrade',
                    'Upgrade': 'websocket',
                    'Sec-WebSocket-Version': '13',
                    'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==',
                    ...headers
                }
            });
            req.on('upgrade', (res, socket, head) => {
                socket.destroy();
                resolve({ statusCode: 101, headers: res.headers });
            });
            req.on('response', (res) => {
                resolve({ statusCode: res.statusCode, headers: res.headers });
            });
            req.on('error', (err) => {
                reject(err);
            });
            req.end();
        });
    }

    async function waitForAuthInfo(child) {
        for (let i = 0; i < 40; i++) {
            await new Promise(r => setTimeout(r, 100));
            if (fs.existsSync(tmpAuthPath)) {
                try {
                    const raw = fs.readFileSync(tmpAuthPath, 'utf8');
                    const info = JSON.parse(raw);
                    if (info.nlPort && info.nlConnectToken) {
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

    it('rejects foreign Origin https://evil.example with HTTP 403 in desktop mode', async function() {
        this.timeout(10000);
        const child = spawn(binPath, ['--load-dir-res', '--window-enable-inspector=false', '--window-hidden=true', '--export-auth-info'], {
            cwd: path.resolve(__dirname, '../bin')
        });

        try {
            const authInfo = await waitForAuthInfo(child);
            const res = await testWsUpgrade(authInfo.nlPort, authInfo.nlConnectToken, {
                'Origin': 'https://evil.example'
            });
            assert.strictEqual(res.statusCode, 403, 'Foreign origin must be rejected with HTTP 403 Forbidden');
        } finally {
            child.kill();
        }
    });

    it('rejects spoofed subdomain Origin http://127.0.0.1.evil.com with HTTP 403', async function() {
        this.timeout(10000);
        const child = spawn(binPath, ['--load-dir-res', '--window-enable-inspector=false', '--window-hidden=true', '--export-auth-info'], {
            cwd: path.resolve(__dirname, '../bin')
        });

        try {
            const authInfo = await waitForAuthInfo(child);
            const res = await testWsUpgrade(authInfo.nlPort, authInfo.nlConnectToken, {
                'Origin': 'http://127.0.0.1.evil.com'
            });
            assert.strictEqual(res.statusCode, 403, 'Subdomain spoofing origin must be rejected with HTTP 403');
        } finally {
            child.kill();
        }
    });

    it('rejects opaque Origin null with HTTP 403', async function() {
        this.timeout(10000);
        const child = spawn(binPath, ['--load-dir-res', '--window-enable-inspector=false', '--window-hidden=true', '--export-auth-info'], {
            cwd: path.resolve(__dirname, '../bin')
        });

        try {
            const authInfo = await waitForAuthInfo(child);
            const res = await testWsUpgrade(authInfo.nlPort, authInfo.nlConnectToken, {
                'Origin': 'null'
            });
            assert.strictEqual(res.statusCode, 403, 'Opaque null origin must be rejected with HTTP 403');
        } finally {
            child.kill();
        }
    });

    it('allows local Origin http://127.0.0.1:<port> and http://localhost in desktop mode', async function() {
        this.timeout(10000);
        const child = spawn(binPath, ['--load-dir-res', '--window-enable-inspector=false', '--window-hidden=true', '--export-auth-info'], {
            cwd: path.resolve(__dirname, '../bin')
        });

        try {
            const authInfo = await waitForAuthInfo(child);

            const res127 = await testWsUpgrade(authInfo.nlPort, authInfo.nlConnectToken, {
                'Origin': `http://127.0.0.1:${authInfo.nlPort}`
            });
            assert.strictEqual(res127.statusCode, 101, 'Local 127.0.0.1 origin must be accepted with HTTP 101');

            const resLocalhost = await testWsUpgrade(authInfo.nlPort, authInfo.nlConnectToken, {
                'Origin': `http://localhost:${authInfo.nlPort}`
            });
            assert.strictEqual(resLocalhost.statusCode, 101, 'Local localhost origin must be accepted with HTTP 101');
        } finally {
            child.kill();
        }
    });

    it('allows non-browser clients with no Origin header', async function() {
        this.timeout(10000);
        const child = spawn(binPath, ['--load-dir-res', '--window-enable-inspector=false', '--window-hidden=true', '--export-auth-info'], {
            cwd: path.resolve(__dirname, '../bin')
        });

        try {
            const authInfo = await waitForAuthInfo(child);
            const res = await testWsUpgrade(authInfo.nlPort, authInfo.nlConnectToken, {});
            assert.strictEqual(res.statusCode, 101, 'Missing Origin header must be allowed for native clients');
        } finally {
            child.kill();
        }
    });

    it('allows any origin in cloud mode per CHANGELOG v5.0.0 specification', async function() {
        this.timeout(10000);
        const child = spawn(binPath, ['--mode=cloud', '--export-auth-info', '--window-enable-inspector=false'], {
            cwd: path.resolve(__dirname, '../bin')
        });

        try {
            const authInfo = await waitForAuthInfo(child);
            const res = await testWsUpgrade(authInfo.nlPort, authInfo.nlConnectToken, {
                'Origin': 'https://evil.example'
            });
            assert.strictEqual(res.statusCode, 101, 'Cloud mode must allow external origins per specification');
        } finally {
            child.kill();
        }
    });
});

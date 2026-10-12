const assert = require('assert');
const http = require('http');
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

describe('os.open command injection security (CWE-78 / GHSA-7678-3cfx-jfc5)', () => {
    const binPath = path.resolve(__dirname, '../bin/neutralino-' +
        (process.platform === 'darwin' ? 'mac_' + process.arch :
         process.platform === 'linux' ? 'linux_' + process.arch : 'win_x64.exe'));
    const tmpAuthPath = path.resolve(__dirname, '../bin/.tmp/auth_info.json');
    const canaryPath = path.resolve(__dirname, '../bin/.tmp/neu_canary_injection');

    function makeWsFrame(payloadStr) {
        const payload = Buffer.from(payloadStr);
        const length = payload.length;
        let header;
        const maskKey = Buffer.from([0x12, 0x34, 0x56, 0x78]);
        if (length <= 125) {
            header = Buffer.from([0x81, 0x80 | length]);
        } else if (length <= 65535) {
            header = Buffer.alloc(4);
            header[0] = 0x81;
            header[1] = 0x80 | 126;
            header.writeUInt16BE(length, 2);
        } else {
            header = Buffer.alloc(10);
            header[0] = 0x81;
            header[1] = 0x80 | 127;
            header.writeBigUInt64BE(BigInt(length), 2);
        }
        const maskedPayload = Buffer.alloc(length);
        for (let i = 0; i < length; i++) {
            maskedPayload[i] = payload[i] ^ maskKey[i % 4];
        }
        return Buffer.concat([header, maskKey, maskedPayload]);
    }

    function callWsMethod(port, connectToken, token, method, data) {
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
            req.on('upgrade', (res, socket) => {
                const reqMsg = JSON.stringify({
                    id: 'test-1',
                    method: method,
                    accessToken: token,
                    data: data
                });
                socket.write(makeWsFrame(reqMsg));
                socket.on('data', () => {
                    socket.destroy();
                    resolve();
                });
                setTimeout(() => {
                    socket.destroy();
                    resolve();
                }, 1000);
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
        try {
            if (fs.existsSync(canaryPath)) fs.unlinkSync(canaryPath);
        } catch (e) {}
    });

    afterEach(() => {
        try {
            if (fs.existsSync(canaryPath)) fs.unlinkSync(canaryPath);
        } catch (e) {}
    });

    it('does NOT execute shell commands injected via double-quote breakout in os.open', async function() {
        this.timeout(10000);
        const child = spawn(binPath, [
            '--load-dir-res',
            '--window-hidden=true',
            '--window-enable-inspector=false',
            '--export-auth-info'
        ], {
            cwd: path.resolve(__dirname, '../bin')
        });

        try {
            const authInfo = await waitForAuthInfo();
            const payload = `"; touch "${canaryPath}"; true "`;
            await callWsMethod(authInfo.nlPort, authInfo.nlConnectToken, authInfo.nlToken, 'os.open', {
                url: payload
            });

            await new Promise(r => setTimeout(r, 500));
            assert.strictEqual(
                fs.existsSync(canaryPath),
                false,
                'VULNERABILITY: Shell command in os.open was executed via double-quote breakout!'
            );
        } finally {
            child.kill();
        }
    });

    it('does NOT execute shell commands injected via command substitution $() in os.open', async function() {
        this.timeout(10000);
        const child = spawn(binPath, [
            '--load-dir-res',
            '--window-hidden=true',
            '--window-enable-inspector=false',
            '--export-auth-info'
        ], {
            cwd: path.resolve(__dirname, '../bin')
        });

        try {
            const authInfo = await waitForAuthInfo();
            const payload = `https://example.com/$(touch "${canaryPath}")`;
            await callWsMethod(authInfo.nlPort, authInfo.nlConnectToken, authInfo.nlToken, 'os.open', {
                url: payload
            });

            await new Promise(r => setTimeout(r, 500));
            assert.strictEqual(
                fs.existsSync(canaryPath),
                false,
                'VULNERABILITY: Shell command in os.open was executed via command substitution $()!'
            );
        } finally {
            child.kill();
        }
    });

    it('does NOT execute shell commands injected via backticks in os.open', async function() {
        this.timeout(10000);
        const child = spawn(binPath, [
            '--load-dir-res',
            '--window-hidden=true',
            '--window-enable-inspector=false',
            '--export-auth-info'
        ], {
            cwd: path.resolve(__dirname, '../bin')
        });

        try {
            const authInfo = await waitForAuthInfo();
            const payload = `https://example.com/\`touch "${canaryPath}"\``;
            await callWsMethod(authInfo.nlPort, authInfo.nlConnectToken, authInfo.nlToken, 'os.open', {
                url: payload
            });

            await new Promise(r => setTimeout(r, 500));
            assert.strictEqual(
                fs.existsSync(canaryPath),
                false,
                'VULNERABILITY: Shell command in os.open was executed via backticks!'
            );
        } finally {
            child.kill();
        }
    });

    it('does NOT execute shell commands injected via semicolon / chaining in os.open', async function() {
        this.timeout(10000);
        const child = spawn(binPath, [
            '--load-dir-res',
            '--window-hidden=true',
            '--window-enable-inspector=false',
            '--export-auth-info'
        ], {
            cwd: path.resolve(__dirname, '../bin')
        });

        try {
            const authInfo = await waitForAuthInfo();
            const payload = `https://example.com; touch "${canaryPath}"`;
            await callWsMethod(authInfo.nlPort, authInfo.nlConnectToken, authInfo.nlToken, 'os.open', {
                url: payload
            });

            await new Promise(r => setTimeout(r, 500));
            assert.strictEqual(
                fs.existsSync(canaryPath),
                false,
                'VULNERABILITY: Shell command in os.open was executed via semicolon chaining!'
            );
        } finally {
            child.kill();
        }
    });
});

const assert = require('assert');
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

describe('Window injectClientLibrary / injectGlobals origin security (CWE-284 / GHSA-cmmf-x4cv-8882)', () => {
    const binPath = path.resolve(__dirname, '../bin/neutralino-' +
        (process.platform === 'darwin' ? 'mac_' + process.arch :
         process.platform === 'linux' ? 'linux_' + process.arch : 'win_x64.exe'));
    const tmpAuthPath = path.resolve(__dirname, '../bin/.tmp/auth_info.json');
    const customConfigPath = path.resolve(__dirname, '../bin/test_inject_config.json');

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

    async function waitForLog(predicate, timeout = 3000) {
        const start = Date.now();
        while (Date.now() - start < timeout) {
            if (predicate()) return true;
            await new Promise(r => setTimeout(r, 50));
        }
        return predicate();
    }

    it('logs a security warning when injectGlobals is enabled with an external remote URL', async function() {
        this.timeout(10000);
        let capturedLogs = '';
        const child = spawn(binPath, [
            '--load-dir-res',
            '--url=https://remote.example.com',
            '--window-inject-globals=true',
            '--window-hidden=true',
            '--window-enable-inspector=false'
        ], {
            cwd: path.resolve(__dirname, '../bin')
        });

        child.stdout.on('data', d => { capturedLogs += d.toString(); });
        child.stderr.on('data', d => { capturedLogs += d.toString(); });

        try {
            const hasWarning = await waitForLog(() => capturedLogs.includes('SECURITY WARNING'));
            assert.ok(hasWarning, 'Must log a security warning when injectGlobals is used with remote URL');
            assert.ok(capturedLogs.includes('https://remote.example.com'), 'Warning must include the remote URL');
        } finally {
            child.kill();
        }
    });

    it('logs a security warning when injectClientLibrary is enabled with an external remote URL', async function() {
        this.timeout(10000);
        let capturedLogs = '';
        const child = spawn(binPath, [
            '--load-dir-res',
            '--url=https://remote.example.com',
            '--window-inject-client-library=true',
            '--window-hidden=true',
            '--window-enable-inspector=false'
        ], {
            cwd: path.resolve(__dirname, '../bin')
        });

        child.stdout.on('data', d => { capturedLogs += d.toString(); });
        child.stderr.on('data', d => { capturedLogs += d.toString(); });

        try {
            const hasWarning = await waitForLog(() => capturedLogs.includes('SECURITY WARNING'));
            assert.ok(hasWarning, 'Must log a security warning when injectClientLibrary is used with remote URL');
        } finally {
            child.kill();
        }
    });

    it('does NOT log a security warning when injectGlobals is used with a local URL', async function() {
        this.timeout(10000);
        let capturedLogs = '';
        const child = spawn(binPath, [
            '--load-dir-res',
            '--url=/',
            '--window-inject-globals=true',
            '--window-hidden=true',
            '--window-enable-inspector=false'
        ], {
            cwd: path.resolve(__dirname, '../bin')
        });

        child.stdout.on('data', d => { capturedLogs += d.toString(); });
        child.stderr.on('data', d => { capturedLogs += d.toString(); });

        try {
            await new Promise(r => setTimeout(r, 1000));
            assert.ok(!capturedLogs.includes('SECURITY WARNING'), 'No security warning should be logged for local app files');
        } finally {
            child.kill();
        }
    });

    it('supports allowedOrigins in config alongside remote URL', async function() {
        this.timeout(10000);
        const config = JSON.parse(fs.readFileSync(path.resolve(__dirname, '../bin/neutralino.config.json'), 'utf8'));
        config.url = 'https://partner.example.com';
        config.modes.window.injectGlobals = true;
        config.modes.window.url = 'https://partner.example.com';
        config.modes.window.allowedOrigins = ['https://partner.example.com', 'https://auth.example.com'];
        fs.writeFileSync(customConfigPath, JSON.stringify(config, null, 2));

        let capturedLogs = '';
        const child = spawn(binPath, [
            '--load-dir-res',
            '--config-file=/test_inject_config.json',
            '--window-hidden=true',
            '--window-enable-inspector=false'
        ], {
            cwd: path.resolve(__dirname, '../bin')
        });

        child.stdout.on('data', d => { capturedLogs += d.toString(); });
        child.stderr.on('data', d => { capturedLogs += d.toString(); });

        try {
            const hasWarning = await waitForLog(() => capturedLogs.includes('SECURITY WARNING'));
            assert.ok(hasWarning, 'Must log security warning for remote URL even if in allowedOrigins');
            assert.ok(capturedLogs.includes('https://partner.example.com'), 'Warning must include the remote URL');
        } finally {
            child.kill();
        }
    });
});

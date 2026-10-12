const assert = require('assert');
const http = require('http');
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

describe('globalVariables script injection / XSS security (CWE-79 / GHSA-4crw-f874-crr2)', () => {
    const binPath = path.resolve(__dirname, '../bin/neutralino-' +
        (process.platform === 'darwin' ? 'mac_' + process.arch :
         process.platform === 'linux' ? 'linux_' + process.arch : 'win_x64.exe'));
    const tmpAuthPath = path.resolve(__dirname, '../bin/.tmp/auth_info.json');
    const customConfigPath = path.resolve(__dirname, '../bin/test_gv_config.json');

    function fetchHttp(port, reqPath) {
        return new Promise((resolve, reject) => {
            http.get(`http://127.0.0.1:${port}${reqPath}`, (res) => {
                let data = '';
                res.on('data', chunk => data += chunk);
                res.on('end', () => resolve({ statusCode: res.statusCode, body: data }));
            }).on('error', reject);
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
            if (fs.existsSync(customConfigPath)) fs.unlinkSync(customConfigPath);
        } catch (e) {}
    });

    afterEach(() => {
        try {
            if (fs.existsSync(customConfigPath)) fs.unlinkSync(customConfigPath);
        } catch (e) {}
    });

    it('does NOT allow JavaScript injection via key or value in globalVariables', async function() {
        this.timeout(10000);
        const baseConfig = JSON.parse(fs.readFileSync(path.resolve(__dirname, '../bin/neutralino.config.json'), 'utf8'));
        baseConfig.globalVariables = {
            "SAFE_VAR": "hello world",
            "EVIL_KEY=1;globalThis.injectedKey=true;//": "dummy",
            "EVIL_VAL": "' + (globalThis.injectedVal=true) + '"
        };
        fs.writeFileSync(customConfigPath, JSON.stringify(baseConfig, null, 2));

        const child = spawn(binPath, [
            '--load-dir-res',
            '--config-file=/test_gv_config.json',
            '--window-hidden=true',
            '--window-enable-inspector=false',
            '--export-auth-info'
        ], {
            cwd: path.resolve(__dirname, '../bin')
        });

        try {
            const authInfo = await waitForAuthInfo();
            const res = await fetchHttp(authInfo.nlPort, '/__neutralino_globals.js');
            assert.strictEqual(res.statusCode, 200);
            assert.ok(res.body.includes('var NL_SAFE_VAR=JSON.parse('), 'Must explicitly use JSON.parse() for variable definitions');

            // Execute the generated script in an isolated sandbox context
            const sandbox = {};
            vm.createContext(sandbox);
            vm.runInContext(res.body, sandbox);

            // Assert that neither key injection nor value injection executed code
            assert.strictEqual(
                sandbox.injectedKey,
                undefined,
                'VULNERABILITY: Key-position breakout executed arbitrary JS code!'
            );
            assert.strictEqual(
                sandbox.injectedVal,
                undefined,
                'VULNERABILITY: Value-position breakout executed arbitrary JS code!'
            );
            assert.strictEqual(sandbox.NL_SAFE_VAR, 'hello world');
        } finally {
            child.kill();
        }
    });

    it('safely serializes all JSON data types, quotes, and escapes HTML script tags', async function() {
        this.timeout(10000);
        const baseConfig = JSON.parse(fs.readFileSync(path.resolve(__dirname, '../bin/neutralino.config.json'), 'utf8'));
        baseConfig.globalVariables = {
            "STR_SINGLE_QUOTE": "O'Reilly",
            "STR_DOUBLE_QUOTE": 'He said "Hello"',
            "STR_HTML_TAG": "</script><script>alert(1)</script>",
            "STR_NEWLINES": "Line 1\nLine 2\r\nLine 3",
            "STR_BACKSLASH": "C:\\Program Files\\App",
            "NUM_INT": 42,
            "NUM_FLOAT": 3.14159,
            "BOOL_TRUE": true,
            "BOOL_FALSE": false,
            "NULL_VAL": null,
            "ARR_VAL": [1, "two", { "three": 3 }],
            "OBJ_VAL": { "nested": "data", "count": 10 }
        };
        fs.writeFileSync(customConfigPath, JSON.stringify(baseConfig, null, 2));

        const child = spawn(binPath, [
            '--load-dir-res',
            '--config-file=/test_gv_config.json',
            '--window-hidden=true',
            '--window-enable-inspector=false',
            '--export-auth-info'
        ], {
            cwd: path.resolve(__dirname, '../bin')
        });

        try {
            const authInfo = await waitForAuthInfo();
            const res = await fetchHttp(authInfo.nlPort, '/__neutralino_globals.js');
            assert.strictEqual(res.statusCode, 200);

            // Assert that literal </script> does not appear in the generated script
            assert.ok(!res.body.includes('</script>'), 'Must not contain literal unescaped </script> tag');
            assert.ok(res.body.includes('<\\/script>'), 'Must escape </script> as <\\/script>');

            // Run in sandbox to verify proper deserialization
            const sandbox = {};
            vm.createContext(sandbox);
            vm.runInContext(res.body, sandbox);

            assert.strictEqual(sandbox.NL_STR_SINGLE_QUOTE, "O'Reilly");
            assert.strictEqual(sandbox.NL_STR_DOUBLE_QUOTE, 'He said "Hello"');
            assert.strictEqual(sandbox.NL_STR_HTML_TAG, "</script><script>alert(1)</script>");
            assert.strictEqual(sandbox.NL_STR_NEWLINES, "Line 1\nLine 2\r\nLine 3");
            assert.strictEqual(sandbox.NL_STR_BACKSLASH, "C:\\Program Files\\App");
            assert.strictEqual(sandbox.NL_NUM_INT, 42);
            assert.strictEqual(sandbox.NL_NUM_FLOAT, 3.14159);
            assert.strictEqual(sandbox.NL_BOOL_TRUE, true);
            assert.strictEqual(sandbox.NL_BOOL_FALSE, false);
            assert.strictEqual(sandbox.NL_NULL_VAL, null);
            assert.deepEqual(sandbox.NL_ARR_VAL, [1, "two", { "three": 3 }]);
            assert.deepEqual(sandbox.NL_OBJ_VAL, { "nested": "data", "count": 10 });
        } finally {
            child.kill();
        }
    });
});

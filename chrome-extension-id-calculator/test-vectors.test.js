#!/usr/bin/env node
/* Test suite for chrome-extension-id-calculator/index.html.
   Each test runs the real inline script of index.html in node:vm with a stub DOM.
   Only the closing line of the script is changed, to expose its functions to the tests.
   Expected IDs were calculated separately with Python hashlib, or are the literal vectors of
   components/crx_file/id_util_unittest.cc at Chromium commit
   79e3aa22eb467575fe0c2db4f9d3dccabf32bddf (fetched 2026-11-09).
   Run with node --test test-vectors.test.js */
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { webcrypto, createHash } = require('node:crypto');

const html = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8');
const inline = [...html.matchAll(/<script>\n([\s\S]*?)<\/script>/g)].pop()[1];
const script = inline.replace(/\}\)\(\);\s*$/,
  'globalThis.__page={hexToAp,idFromHexFull,pathToBytes,sha256Hex,parseKeyInput,normalizePath,isPrivateDer,refusePrivate};})();');

function makeNode() {
  return {
    children: [], own: '', value: '', hidden: false, className: '', listeners: {},
    appendChild(c) { this.children.push(c); return c; },
    removeChild(c) { this.children.splice(this.children.indexOf(c), 1); },
    get firstChild() { return this.children[0] || null; },
    addEventListener(t, f) { (this.listeners[t] = this.listeners[t] || []).push(f); },
    set textContent(v) { this.own = String(v); this.children = []; },
    get textContent() { return this.own + this.children.map((c) => c.textContent).join('\n'); },
  };
}
function boot(options = {}) {
  const els = {};
  const byId = (id) => els[id] || (els[id] = makeNode());
  const sandbox = { document: { getElementById: byId, createElement: () => makeNode() }, atob, TextEncoder, console, setTimeout };
  sandbox.window = { addEventListener(t, f) { (sandbox.windowListeners = sandbox.windowListeners || {})[t] = f; } };
  if (!options.noCrypto) sandbox.crypto = webcrypto;
  vm.createContext(sandbox);
  vm.runInContext(script, sandbox, { filename: 'index.html' });
  return { els, sandbox, api: sandbox.__page };
}
const tick = (ms = 10) => new Promise((r) => setTimeout(r, ms));
async function settle(out) {
  for (let i = 0; i < 300; i += 1) {
    const t = out.textContent;
    if (!/Step 1\./.test(t) || /Step 4\./.test(t)) break;
    await tick(5);
  }
  await tick(2);
}
async function run(fields, page = boot()) {
  for (const f of ['path', 'key', 'expected']) page.els['cei-' + f].value = fields[f] || '';
  page.els['cei-run'].listeners.click[0]();
  await settle(page.els['cei-out']);
  return page.els['cei-out'].textContent;
}

/* kPublicKeyInfo from id_util_unittest.cc. */
const kPublicKeyInfo = Buffer.from(
  '30819f300d06092a864886f70d010101050003818d0030818902818100b87f2b20dc7c9b' +
  '0cdc5161990d360fd46688085584d53abf2ba464857b0c04133f8df4bc380d49fe6bc45a' +
  'b040533ad766090f9e367430da8a314f1f1450d7c7209417de4eb9575e7e0ae5b2657a89' +
  '4eb647ff1cbdb73813af4785843233f31749bfe996d0d6146f138dc5fc2c72baacea7e18' +
  '5356a683a2ce9393e71f0fe60f0203010001', 'hex');
const pkiB64 = kPublicKeyInfo.toString('base64');
const demoKey = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxVrV4tBX6aS/sAYQ01xWJlblWIk9xfk1vppZ2DvViOgpKkTynHKGws2eCZb/+1GnU9U3l0tKLUtVMDK3babyxKNwPGiALtQ3Xz3NPYhY+AdqlscqhdEVv99ysIszVHFmqQnWNPiL9plYOfAVf7hkhDuvdnuPILL1MalRJBJkS4y0VmV0MUdvKaACcruguItooveojmtcttsk0xCZhQp9HpnWNmNliMC1ozC7jA3v7PUjC5+LaznNBvLmjnkJdA7iEbvNtudoc7N1Gf/9l+TJjyFELmmJPkILTGxLObiNWnCTLhuUk/utqWM1L7t9TPiLJnltNuhSh15QteAUWueh4wIDAQAB';
const demoId = 'afnphhnioekcdchdjhgfmcnbemagjabl';
const posixExampleId = 'olbencniebbeagnnpldmdoogijjbfdkm';

test('GenerateId(kPublicKeyInfo) through the key field', async () => {
  assert.match(await run({ key: pkiB64 }), /melddjfinppjdikinhbgehiennejpfhp/);
});
test('GenerateId("test") through the key field', async () => {
  assert.match(await run({ key: Buffer.from('test').toString('base64') }), /jpignaibiiemhngfjkcpokkamffknabf/);
});
test('GenerateId("_") through the key field', async () => {
  assert.match(await run({ key: Buffer.from('_').toString('base64') }), /ncocknphbhhlhkikpnnlmbcnbgdempcd/);
});
test('GenerateId(long string) through the key field', async () => {
  const b64 = Buffer.from('this_string_is_longer_than_a_single_sha256_hash_digest').toString('base64');
  assert.match(await run({ key: b64 }), /jimneklojkjdibfkgiiophfhjhbdgcfi/);
});
test('GenerateIdFromHash(kPublicKeyInfo) with idFromHexFull', () => {
  assert.equal(boot().api.idFromHexFull(kPublicKeyInfo.toString('hex')), 'daibjpdaanagajckigeiigphanababab');
});
test('GenerateIdFromHex vectors with hexToAp', () => {
  const { api } = boot();
  assert.equal(api.hexToAp('_'), 'a');
  assert.equal(api.hexToAp('1913a5e0a6cad30b6f03e176177e0d7ed62c5d6700a9c66da556d7c3f5d6a47e'), 'bjbdkfoakgmkndalgpadobhgbhhoanhongcmfnghaakjmggnkffgnhmdpfngkeho');
});
test('GenerateIdForPath POSIX vector', async () => {
  assert.match(await run({ path: '/path/to/file.ext' }), /lnkgfdknojmdambfcanadbhmfjfljobb/);
});
test('GenerateIdForPath Windows vector with pathToBytes in UTF-16LE', async () => {
  const { api } = boot();
  assert.equal(api.idFromHexFull(await api.sha256Hex(api.pathToBytes('/path/to/file.ext', true))), 'jjlkojfgbeklddcpckipekckcmgcbfjn');
});
test('HashedIdInHexSha256 vector with sha256Hex', async () => {
  const { api } = boot();
  assert.equal((await api.sha256Hex(new TextEncoder().encode('abcdefghijklmnopabcdefghijklmnop'))).toUpperCase(), 'DF43A9994ADFFA1484525827764397252D90EF618363E5D381A158AC38B11A8A');
});
test('HashedIdInHex SHA-1 vector (the page has no SHA-1 code, checked with node:crypto)', () => {
  assert.equal(createHash('sha1').update('abcdefghijklmnopabcdefghijklmnop').digest('hex').toUpperCase(), 'ACD66AF886BA7B085B41B4382BC39D1855BC18FE');
});
test('PEM with headers and line breaks gives the key ID', async () => {
  const pem = '-----BEGIN PUBLIC KEY-----\n' + pkiB64.replace(/(.{64})/g, '$1\n') + '\n-----END PUBLIC KEY-----\n';
  assert.match(await run({ key: pem }), /melddjfinppjdikinhbgehiennejpfhp/);
});
test('PEM with CRLF line breaks gives the key ID', async () => {
  const pem = '-----BEGIN PUBLIC KEY-----\r\n' + pkiB64.replace(/(.{64})/g, '$1\r\n') + '\r\n-----END PUBLIC KEY-----\r\n';
  assert.match(await run({ key: pem }), /melddjfinppjdikinhbgehiennejpfhp/);
});
test('Key with spaces or line breaks inside the base64 is refused', async () => {
  for (const key of [pkiB64.slice(0, 40) + ' ' + pkiB64.slice(40), pkiB64.slice(0, 40) + '\n' + pkiB64.slice(40), '-----BEGIN PUBLIC KEY----- ' + pkiB64 + ' -----END PUBLIC KEY-----']) {
    const t = await run({ key });
    assert.match(t, /Chromium would refuse/);
    assert.doesNotMatch(t, /Step 1/);
  }
});
test('A bare key with a trailing newline gives the ID and a warning', async () => {
  const t = await run({ key: pkiB64 + '\n' });
  assert.match(t, /melddjfinppjdikinhbgehiennejpfhp/);
  assert.match(t, /removed the spaces or line breaks/);
});
test('A PEM with a trailing newline needs no warning', async () => {
  const t = await run({ key: '-----BEGIN PUBLIC KEY-----\n' + pkiB64 + '\n-----END PUBLIC KEY-----\n' });
  assert.match(t, /melddjfinppjdikinhbgehiennejpfhp/);
  assert.doesNotMatch(t, /removed the spaces/);
});
test('Text that is not base64 is refused', async () => {
  const t = await run({ key: 'not base64 !!!' });
  assert.match(t, /Chromium would refuse/);
  assert.doesNotMatch(t, /Step 1/);
});
test('Unpadded base64, three padding characters and a missing PEM footer are refused', async () => {
  for (const key of ['QUI', 'QUI===', '-----BEGIN PUBLIC KEY-----\nQUJD\n']) {
    const t = await run({ key });
    assert.match(t, /Chromium would refuse/);
    assert.doesNotMatch(t, /Step 1/);
  }
});
test('A key over 100 KiB is refused', async () => {
  const t = await run({ key: 'QUJD'.repeat(25601) });
  assert.match(t, /100 KiB/);
});
test('Empty input asks for input', async () => {
  assert.match(await run({}), /Paste a folder path/);
});
test('Windows lowercase drive letter is upper-cased, UTF-16LE', async () => {
  assert.match(await run({ path: 'c:\\Users\\Mike\\my ext' }), /ogjgcfifammbipkgfaonllbefeckhklm/);
});
test('Windows forward slashes and UNC paths', () => {
  const { api } = boot();
  assert.equal(api.normalizePath('C:/Users/x/ext').path, 'C:\\Users\\x\\ext');
  assert.equal(api.normalizePath('\\\\server\\share\\ext').path, '\\\\server\\share\\ext');
});
test('POSIX path with non-ASCII letters is UTF-8', async () => {
  assert.match(await run({ path: '/Users/you/R\u00f6ntgen-\u65e5\u672c' }), /mnheppbfekglpiaekaljfafjcjoinaam/);
});
test('A trailing slash is removed before the hash', async () => {
  assert.match(await run({ path: '/Users/you/my-extension/' }), new RegExp(posixExampleId));
});
test('Relative paths are refused', async () => {
  for (const p of ['my-extension', '~/ext', './ext']) {
    const t = await run({ path: p });
    assert.match(t, /absolute path/);
    assert.doesNotMatch(t, /Step 1/);
  }
});
test('Key plus path, the key wins', async () => {
  const t = await run({ key: demoKey, path: '/tmp/x' });
  assert.match(t, new RegExp(demoId));
  assert.match(t, /You entered a key and a path/);
});
test('Expected ID match names the rule', async () => {
  const t = await run({ path: '/path/to/file.ext', expected: 'LNKGFDKNOJMDAMBFCANADBHMFJFLJOBB' });
  assert.match(t, /Match/);
  assert.match(t, /path rule/);
});
test('Expected ID mismatch names the key rule and the store difference', async () => {
  const t = await run({ key: demoKey, expected: 'a'.repeat(32) });
  assert.match(t, /No match/);
  assert.match(t, /key rule/);
  assert.match(t, /Web Store ID and an unpacked ID differ/);
});
test('An expected value of the wrong form is reported', async () => {
  assert.match(await run({ path: '/x/y', expected: 'hello' }), /Not a valid ID/);
});
test('Private keys are refused in each field, with no bytes shown', async () => {
  const pemKey = '-----BEGIN PRIVATE KEY-----\nMIIBVQIBADAN\n-----END PRIVATE KEY-----';
  const opensshBare = Buffer.from('openssh-key-v1\0xxxxxxxxxxxxxxxx').toString('base64');
  const pkcs8 = Buffer.from('30130201003000' + '00'.repeat(14), 'hex').toString('base64');
  const sec1 = Buffer.from('30770201010420' + 'ab'.repeat(114), 'hex').toString('base64');
  const encrypted = Buffer.from('301a300b06092a864886f70d01050d040b' + '00'.repeat(11), 'hex').toString('base64');
  for (const secret of [pemKey, opensshBare, pkcs8, sec1, encrypted, '-----BEGIN PUBLIC KEY-----\n' + pkcs8 + '\n-----END PUBLIC KEY-----']) {
    for (const field of ['key', 'path', 'expected']) {
      const t = await run({ [field]: secret });
      assert.match(t, /private key, so the tool refused/, field);
      assert.doesNotMatch(t, /Step 1|abab/);
    }
  }
});
test('A real public key in the same form as a private key is not refused', () => {
  const { api } = boot();
  assert.equal(api.isPrivateDer(Buffer.from(demoKey, 'base64')), false);
  assert.equal(api.isPrivateDer(kPublicKeyInfo), false);
});
test('Editing an input after a result removes the result', async () => {
  const page = boot();
  await run({ path: '/x/y' }, page);
  assert.match(page.els['cei-out'].textContent, /Step 4/);
  page.els['cei-path'].listeners.input[0]();
  assert.equal(page.els['cei-out'].textContent, '');
  assert.equal(page.els['cei-out'].hidden, true);
});
test('A result in flight is dropped after an edit', async () => {
  const page = boot();
  page.els['cei-path'].value = '/x/y';
  page.els['cei-run'].listeners.click[0]();
  page.els['cei-path'].listeners.input[0]();
  await tick(30);
  assert.equal(page.els['cei-out'].textContent, '');
});
test('Double click gives one result', async () => {
  const page = boot();
  page.els['cei-path'].value = '/x/y';
  page.els['cei-run'].listeners.click[0]();
  page.els['cei-run'].listeners.click[0]();
  await tick(30);
  await settle(page.els['cei-out']);
  const t = page.els['cei-out'].textContent;
  assert.equal(t.match(/Step 1\./g).length, 1);
  assert.equal(t.match(/Step 4\./g).length, 1);
});
test('Missing crypto.subtle gives a message', async () => {
  const page = boot({ noCrypto: true });
  assert.match(await run({ path: '/x/y' }, page), /does not offer Web Crypto/);
});
test('The worked example IDs in the table equal the tool output', async () => {
  assert.match(html, new RegExp('<td>' + posixExampleId + '</td>'));
  assert.match(await run({ path: '/Users/you/my-extension' }), new RegExp(posixExampleId));
  assert.match(html, new RegExp('<td>ccpdamacfjmiedkhelgfhkffjknaafij</td>'));
  assert.match(await run({ path: 'c:\\Users\\you\\my-extension' }), /ccpdamacfjmiedkhelgfhkffjknaafij/);
  assert.match(html, new RegExp('<td>' + demoId + '</td>'));
  assert.match(await run({ key: demoKey }), new RegExp(demoId));
});

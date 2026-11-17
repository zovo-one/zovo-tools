// Unit test for convertManifest() extracted from index.html (no DOM needed).
// Run: node --test
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const html = readFileSync(new URL("./index.html", import.meta.url), "utf8");
const start = html.indexOf("function convertManifest(src) {");
if (start === -1) throw new Error("convertManifest not found in index.html");
// Grab the function body by brace matching.
let depth = 0, end = -1;
for (let i = html.indexOf("{", start); i < html.length; i++) {
  if (html[i] === "{") depth++;
  else if (html[i] === "}") { depth--; if (depth === 0) { end = i + 1; break; } }
}
if (end === -1) throw new Error("could not extract convertManifest body");
const convertManifest = new Function("return (" + html.slice(start, end) + ")")();

test("manifest_version 2 -> 3 with change log", () => {
  const r = convertManifest(JSON.stringify({
    manifest_version: 2,
    name: "t", version: "1.0",
    background: { scripts: ["bg.js"], persistent: false },
    permissions: ["storage", "tabs", "https://example.com/*"]
  }));
  assert.equal(r.output.manifest_version, 3);
  assert.ok(r.output.background.service_worker.includes("bg.js"));
  assert.equal(r.output.permissions.includes("https://example.com/*"), false);
  assert.ok(r.output.host_permissions.includes("https://example.com/*"));
  assert.ok(r.changes.some(c => /manifest_version/.test(c.text)));
  assert.ok(r.changes.some(c => /service_worker|background/.test(c.text)));
  assert.ok(r.changes.some(c => /host_permissions|example\.com/.test(c.text)));
});

test("persistent background becomes non-persistent service worker note", () => {
  const r = convertManifest(JSON.stringify({
    manifest_version: 2, name: "t", version: "1",
    background: { page: "bg.html" }
  }));
  assert.ok(r.changes.some(c => /DOM|document|window|manual|page/i.test(c.text + (r.manual.map(m=>m.text).join(" ") || ""))));
});

test("browser_action renamed to action", () => {
  const r = convertManifest(JSON.stringify({
    manifest_version: 2, name: "t", version: "1",
    browser_action: { default_popup: "p.html" }
  }));
  assert.ok(r.output.action && r.output.action.default_popup === "p.html");
  assert.equal(r.output.browser_action, undefined);
});

test("web_accessible_resources strings become object form", () => {
  const r = convertManifest(JSON.stringify({
    manifest_version: 2, name: "t", version: "1",
    web_accessible_resources: ["img/*.png"]
  }));
  const war = r.output.web_accessible_resources;
  assert.ok(Array.isArray(war) && typeof war[0] === "object");
  assert.deepEqual(war[0].resources, ["img/*.png"]);
  assert.ok(war[0].matches);
});

test("CSP unsafe values stripped and reported", () => {
  const r = convertManifest(JSON.stringify({
    manifest_version: 2, name: "t", version: "1",
    content_security_policy: "script-src 'self' 'unsafe-eval' https://cdn.example.com; object-src 'self'"
  }));
  const csp = r.output.content_security_policy;
  const s = typeof csp === "string" ? csp : (csp["extension_pages"] || "");
  assert.ok(!/unsafe-eval|cdn\.example\.com/.test(s));
  assert.ok(r.changes.some(c => /content_security_policy|CSP/i.test(c.text)) || r.csp.bad.length > 0);
});

test("commands _execute_browser_action renamed", () => {
  const r = convertManifest(JSON.stringify({
    manifest_version: 2, name: "t", version: "1",
    commands: { "_execute_browser_action": { suggested_key: { default: "Ctrl+Shift+Y" }, description: "d" } }
  }));
  assert.ok(r.output.commands["_execute_action"]);
});

test("comments and trailing commas produce a parse error with position, no silent drop", () => {
  const r1 = convertManifest('{\n  "manifest_version": 2, // comment\n  "name": "t"\n}');
  assert.ok(r1.error && /position|line|column|Parse|Syntax/i.test(r1.error));
  const r2 = convertManifest('{"manifest_version": 2, "name": "t",}');
  assert.ok(r2.error);
});

test("already-V3 manifest passes through without a manifest_version change", () => {
  const r = convertManifest(JSON.stringify({
    manifest_version: 3, name: "t", version: "1", permissions: ["storage"]
  }));
  assert.equal(r.output.manifest_version, 3);
  assert.ok(!r.changes.some(c => /manifest_version.*2|2.*3/.test(c.text)));
});

test("malformed input never renders NaN/undefined into output JSON", () => {
  const r = convertManifest("not json at all");
  assert.ok(r.error);
  assert.ok(!/NaN|undefined|Infinity/.test(JSON.stringify(r)));
});

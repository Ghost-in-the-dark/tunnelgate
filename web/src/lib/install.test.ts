import { test } from 'node:test'
import assert from 'node:assert/strict'

import { COMMAND_VARIANTS, commandFor } from './install.ts'

// The panel used to offer "curl | sh" and "wget | sh" and derive the second by regex-replacing
// 'curl -fsSL' with 'uclient-fetch -qO-'. Both halves were wrong for the hardware they targeted:
// stock OpenWrt ships no curl, its /usr/bin/wget is a symlink to uclient-fetch, and the busybox
// wget applet does not exist, so the "wget" variant was dead on arrival. The server now emits one
// command that probes the fetcher itself. These tests exist to keep the panel from editing it again.

const SERVED = [
  "U='https://tok_abc123@gate.example.com/api/v1/routers/install?os=linux'; F=/tmp/tg-install.$$.sh",
  'if command -v curl >/dev/null 2>&1; then curl -fsSL -o "$F" "$U"',
  'elif command -v wget >/dev/null 2>&1; then wget -q -O "$F" "$U"',
  "else echo 'TunnelGate: neither curl nor wget is installed on this router' >&2; exit 1; fi",
  'grep -q \'TunnelGate router agent installer\' "$F" 2>/dev/null || { echo "TunnelGate: the panel did not return the installer; mint a fresh install command and retry" >&2; rm -f "$F"; exit 1; }',
  'sh "$F"',
].join('\n')

const SCRIPT_URL = 'https://gate.example.com/api/v1/routers/install?os=linux'

test('the install variant returns the served command byte for byte', () => {
  assert.equal(commandFor('install', SERVED, SCRIPT_URL), SERVED)
})

test('the install variant keeps a trailing newline and trailing spaces intact', () => {
  const awkward = 'U="x"; F=/tmp/f.sh  \nif true; then :; fi\n'
  const out = commandFor('install', awkward, SCRIPT_URL)
  assert.equal(out, awkward)
  assert.equal(out.split('\n').length, awkward.split('\n').length)
  // Two spaces before the escaped newline: collapsing whitespace changes shell semantics.
  assert.ok(out.includes('  \n'))
})

test('the install variant preserves every newline of a multi-line command', () => {
  const out = commandFor('install', SERVED, SCRIPT_URL)
  assert.equal(out.split('\n').length, SERVED.split('\n').length)
  assert.ok(out.startsWith("U='https://tok_abc123@"))
  assert.ok(out.endsWith('sh "$F"'))
  // A command pasted from a <pre> must arrive with its line breaks, or only line 1 runs.
  assert.ok(out.includes('\n' + 'sh "$F"'))
})

test('no variant rewrites curl into another fetcher', () => {
  for (const variant of COMMAND_VARIANTS) {
    const out = commandFor(variant.id, SERVED, SCRIPT_URL)
    assert.ok(!out.includes('uclient-fetch -qO-'), `${variant.id} rewrote the fetcher`)
  }
  // The served text still mentions curl - the command probes for it - and that must survive.
  assert.ok(commandFor('install', SERVED, SCRIPT_URL).includes('command -v curl'))
})

test('the install variant performs no string surgery at all', () => {
  const probe = 'curl -fsSL curl -fsS curl -fsSLk curl -sSL curl -H "X-Bootstrap-Token: t" | sh'
  assert.equal(commandFor('install', probe, SCRIPT_URL), probe)
})

test('the manual variant is the bare token-less script URL', () => {
  assert.equal(commandFor('manual', SERVED, SCRIPT_URL), SCRIPT_URL)
  // It is a pointer, not a credential: the manual URL must never carry the token.
  assert.ok(!commandFor('manual', SERVED, SCRIPT_URL).includes('tok_abc123'))
})

test('the variant list is exactly the two ways to install', () => {
  assert.deepEqual(
    COMMAND_VARIANTS.map((v) => v.id),
    ['install', 'manual'],
  )
  assert.equal(COMMAND_VARIANTS.length, 2)
  for (const variant of COMMAND_VARIANTS) {
    assert.ok(variant.label.length > 0)
    // No fetcher is named in the UI copy any more: the command picks one at runtime.
    assert.ok(!/curl|wget|uclient/i.test(variant.label), `${variant.id} names a fetcher`)
  }
})

test('every declared variant is handled by commandFor', () => {
  for (const variant of COMMAND_VARIANTS) {
    const out = commandFor(variant.id, SERVED, SCRIPT_URL)
    assert.equal(typeof out, 'string')
    assert.ok(out.length > 0)
  }
})

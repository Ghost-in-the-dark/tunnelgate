import { test } from 'node:test'
import assert from 'node:assert/strict'

import { isOpenableUrl, unopenableReason } from './external.ts'

// The case that produced the bug report: the panel built https://lab-router.192.168.88.107/
// because TUNNELGATE_SUBDOMAIN_SUFFIX was an IP address. It renders correctly in the UI and
// the browser refuses it outright, so every check here is about telling those apart.

test('a hostname routed through a real domain opens', () => {
  const url = 'https://lab-router.example.com/__tg/enter'
  assert.equal(isOpenableUrl(url), true)
  assert.equal(unopenableReason(url), '')
})

test('a hostname routed through a duckdns-style domain opens', () => {
  const url = 'https://lab-router.example.duckdns.org/__tg/enter?t=abc'
  assert.equal(isOpenableUrl(url), true)
  assert.equal(unopenableReason(url), '')
})

test('an IP address as the subdomain suffix is refused, and named as the cause', () => {
  const url = 'https://lab-router.192.168.88.107/__tg/enter'
  assert.equal(isOpenableUrl(url), false)
  const reason = unopenableReason(url)
  assert.match(reason, /subdomain suffix is an IP address/)
  // The operator needs the setting name and a concrete replacement, not a browser error.
  assert.match(reason, /TUNNELGATE_SUBDOMAIN_SUFFIX/)
  assert.match(reason, /router\.example\.com/)
  // Path routing is the alternative for anyone without a wildcard-capable domain.
  assert.match(reason, /TUNNELGATE_ROUTE_MODE=path/)
  assert.match(reason, /TUNNELGATE_GATEWAY_HOST/)
})

// Path mode is the answer for a free dynamic-DNS name: one host, one prefix per router.
// Nothing about that form is unusual for a browser, so these must all pass untouched.
test('a path-routed URL under one gateway host opens', () => {
  const launch = 'https://gate.example.duckdns.org/lab-router/__tg/enter'
  assert.equal(isOpenableUrl(launch), true)
  assert.equal(unopenableReason(launch), '')
  assert.equal(unopenableReason('https://gate.example.duckdns.org/lab-router/'), '')
  // A port in the gateway does not change any of that.
  assert.equal(unopenableReason('https://gate.example.duckdns.org:8443/lab-router/'), '')
})

test('a path-routed URL whose prefix looks like an IP is still openable', () => {
  // The IP heuristic only looks at the HOST, so a slug such as "192" cannot trip it.
  assert.equal(unopenableReason('https://gate.example.com/192.168.1.1/'), '')
})

test('the IP-suffix reason also fires for a bare public URL', () => {
  assert.match(
    unopenableReason('https://lab-router.192.168.88.107'),
    /subdomain suffix is an IP address/,
  )
})

test('a plain IP and port as the whole host is still openable', () => {
  // A host that is ONLY an IP is a valid URL - it is the suffixed form above that is not.
  assert.equal(isOpenableUrl('http://127.0.0.1:8089/login'), true)
  assert.equal(unopenableReason('http://127.0.0.1:8089/login'), '')
})

test('a missing route is reported as missing, not as invalid', () => {
  assert.equal(unopenableReason(null), 'There is no public URL for this router yet.')
  assert.equal(unopenableReason(''), 'There is no public URL for this router yet.')
  assert.equal(isOpenableUrl(null), false)
})

test('a non-http scheme is refused', () => {
  assert.equal(isOpenableUrl('ftp://panel.example.com/'), false)
  assert.match(unopenableReason('ftp://panel.example.com/'), /not http\(s\)/)
})

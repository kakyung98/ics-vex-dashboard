const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

function bridge() {
  const calls = [];
  const context = {
    URL, Response, Request,
    location: new URL('http://localhost:8100/source.html'),
    sessionStorage: {getItem: () => null, removeItem: () => {}},
    document: {readyState: 'loading', addEventListener: () => {}},
    window: {fetch: async (url, options) => {
      calls.push({url: String(url), options});
      return new Response(JSON.stringify({
        'icsa-26-302-03': {id: 'icsa-26-302-03', overview: 'Saved CISA content'}
      }), {headers: {'Content-Type': 'application/json'}});
    }}
  };
  vm.runInNewContext(fs.readFileSync(path.resolve(__dirname, '../../site/pages-bridge.js'), 'utf8'), context);
  return {fetch: context.window.fetch, calls};
}

test('advisory snapshots bypass stale browser data', async () => {
  const b = bridge();
  await b.fetch('/api/advisories/list');
  assert.equal(b.calls[0].url, 'http://localhost:8100/advisories_list.json');
  assert.equal(b.calls[0].options.cache, 'no-store');
});

test('uppercase and lowercase advisory IDs load the saved detail shard', async () => {
  for (const id of ['ICSA-26-302-03', 'icsa-26-302-03']) {
    const b = bridge();
    const response = await b.fetch('/api/advisory/' + id);
    assert.equal(response.status, 200);
    assert.equal((await response.json()).overview, 'Saved CISA content');
    assert.equal(b.calls[0].url, 'http://localhost:8100/advisory_details_26.json');
    assert.equal(b.calls[0].options.cache, 'no-store');
  }
});

test('invalid advisory IDs do not request a shard', async () => {
  const b = bridge();
  assert.equal((await b.fetch('/api/advisory/not-an-advisory')).status, 404);
  assert.equal(b.calls.length, 0);
});

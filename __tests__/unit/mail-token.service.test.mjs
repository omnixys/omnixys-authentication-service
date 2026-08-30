import assert from 'node:assert/strict';
import test from 'node:test';
import { of } from 'rxjs';

process.env.KC_CLIENT_ID = 'nexys';
process.env.KC_CLIENT_SECRET = 'test-client-secret';
process.env.KC_URL = 'https://keycloak.example.test';
process.env.KC_REALM = 'omnixys';

const { MailTokenService } = await import(
  '../../dist/authentication/mail/mail-token.service.js'
);

const source = {
  sub: 'user-1',
  preferred_username: 'caleb',
  azp: 'nexys',
  exp: Math.floor(Date.now() / 1000) + 300,
};
const downstream = {
  ...source,
  aud: 'stalwart',
};

function fixture({ cached = null, exchanged = downstream } = {}) {
  const values = new Map();
  if (cached) values.set('mail:downstream:v1:cached', cached);
  const requests = [];
  const http = {
    request(input) {
      requests.push(input);
      return of({
        status: 200,
        data: {
          access_token: 'downstream-token',
          expires_in: 120,
          token_type: 'Bearer',
        },
      });
    },
  };
  let verification = 0;
  const readService = {
    async verifyAccessToken() {
      verification += 1;
      return verification === 1 ? source : exchanged;
    },
  };
  const cache = {
    key: (key) => `authentication:${key}`,
    rawGet: async (key) => values.get(key) ?? null,
    rawSet: async (key, value) => values.set(key, value),
    rawDelete: async (key) => values.delete(key),
  };
  const locks = {
    acquireLock: async () => 'lock-token',
    releaseLock: async () => true,
  };
  const jwe = {
    encrypt: async (value) => `encrypted:${JSON.stringify(value)}`,
    decrypt: async (value) => JSON.parse(value.slice('encrypted:'.length)),
  };
  const logger = {
    log: () => ({ info() {}, warn() {}, debug() {}, error() {} }),
  };
  return {
    service: new MailTokenService(logger, http, readService, cache, locks, jwe),
    requests,
    values,
  };
}

test('exchanges a nexys platform token with the complete RFC 8693 request', async () => {
  const { service, requests, values } = fixture();
  const result = await service.issue('platform-token');

  assert.equal(result.accessToken, 'downstream-token');
  assert.equal(result.tokenType, 'Bearer');
  assert.equal(requests.length, 1);
  const body = new URLSearchParams(requests[0].data);
  assert.equal(
    body.get('grant_type'),
    'urn:ietf:params:oauth:grant-type:token-exchange',
  );
  assert.equal(body.get('client_id'), 'nexys');
  assert.equal(body.get('scope'), 'stalwart-downstream');
  assert.equal(body.get('audience'), 'stalwart');
  assert.equal(
    body.get('requested_token_type'),
    'urn:ietf:params:oauth:token-type:access_token',
  );
  assert.match([...values.values()][0], /^encrypted:/);
  assert.doesNotMatch([...values.values()][0], /^\{/);
});

test('rejects an exchanged token without the exact stalwart audience', async () => {
  const { service } = fixture({ exchanged: { ...downstream, aud: 'other' } });
  await assert.rejects(() => service.issue('platform-token'), {
    code: 'AUTHENTICATION_STATE_INVALID',
  });
});

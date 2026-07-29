import assert from 'node:assert/strict';
import test from 'node:test';
import { of, throwError } from 'rxjs';

process.env.KC_CLIENT_ID = 'test-client';
process.env.KC_CLIENT_SECRET = 'test-secret';
process.env.KC_ADMIN_USERNAME = 'admin';
process.env.KC_ADMIN_PASSWORD = 'admin-password';

const { AuthenticateBaseService } = await import(
  '../../dist/authentication/services/keycloak-base.service.js'
);

const sink = { debug() {}, info() {}, warn() {}, error() {} };
const logger = { log: () => sink };

class TestKeycloakService extends AuthenticateBaseService {
  request(method, url, config, behavior) {
    return this.kcRequest(method, url, config, behavior);
  }

  adminToken() {
    return this.getAdminToken();
  }
}

test('end-user invalid_grant remains INVALID_CREDENTIALS without leaking identity', async () => {
  const service = new TestKeycloakService(logger, {
    request: () =>
      throwError(() => keycloakError(400, 'invalid_grant', 'Invalid user credentials')),
  });

  const result = await service.request(
    'post',
    '/token',
    { adminAuth: false },
    { mapTo: 'null-on-401' },
  );
  assert.equal(result, null);
});

test('invalid client is not collapsed into end-user invalid credentials', async () => {
  const service = new TestKeycloakService(logger, {
    request: () =>
      throwError(() => keycloakError(401, 'invalid_client', 'Invalid client secret')),
  });

  await assert.rejects(
    service.request(
      'post',
      '/token',
      { adminAuth: false },
      { mapTo: 'null-on-401' },
    ),
    (error) =>
      error.code === 'IDENTITY_PROVIDER_CLIENT_CONFIGURATION_INVALID' &&
      error.httpStatus === 500 &&
      JSON.stringify(error).includes('client secret') === false,
  );
});

test('wrong administrator username or password maps to 401', async () => {
  const service = new TestKeycloakService(logger, {
    post: () =>
      throwError(() => keycloakError(400, 'invalid_grant', 'Invalid user credentials')),
  });

  await assert.rejects(
    service.adminToken(),
    (error) =>
      error.code === 'IDENTITY_PROVIDER_ADMIN_CREDENTIALS_INVALID' &&
      error.httpStatus === 401,
  );
});

test('administrator without realm permissions maps to 403', async () => {
  const service = new TestKeycloakService(logger, {
    post: () => of({ status: 200, data: { access_token: 'admin-token', expires_in: 60 } }),
    request: () => throwError(() => keycloakError(403, 'forbidden', 'Forbidden')),
  });

  await assert.rejects(
    service.request('get', '/admin/realms/omnixys/users'),
    (error) =>
      error.code === 'IDENTITY_PROVIDER_ADMIN_FORBIDDEN' &&
      error.httpStatus === 403,
  );
});

test('rate limits, network failures and malformed responses remain distinguishable', async () => {
  const rateLimited = new TestKeycloakService(logger, {
    request: () => throwError(() => keycloakError(429, 'temporarily_unavailable', 'Slow down')),
  });
  await assert.rejects(
    rateLimited.request('get', '/resource', { adminAuth: false }),
    (error) =>
      error.code === 'IDENTITY_PROVIDER_RATE_LIMITED' &&
      error.httpStatus === 429 &&
      error.retryable === true,
  );

  const unavailable = new TestKeycloakService(logger, {
    request: () => throwError(() => Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' })),
  });
  await assert.rejects(
    unavailable.request('get', '/resource', { adminAuth: false }),
    (error) =>
      error.code === 'IDENTITY_PROVIDER_UNAVAILABLE' &&
      error.httpStatus === 503 &&
      error.retryable === true,
  );

  const malformed = new TestKeycloakService(logger, {
    post: () => of({ status: 200, data: { expires_in: 60 } }),
  });
  await assert.rejects(
    malformed.adminToken(),
    (error) =>
      error.code === 'IDENTITY_PROVIDER_RESPONSE_INVALID' &&
      error.httpStatus === 502,
  );
});

function keycloakError(status, error, error_description) {
  return Object.assign(new Error(error_description), {
    response: { status, data: { error, error_description } },
  });
}

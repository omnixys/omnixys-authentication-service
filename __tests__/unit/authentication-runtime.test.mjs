import assert from 'node:assert/strict';
import test from 'node:test';
import 'reflect-metadata';

const { ContextAccessor } = await import('@omnixys/context-ts');
const { InvalidCredentialsException } = await import('@omnixys/security-ts');
const { AuthenticationStateException } = await import(
  '../../dist/authentication/errors/authentication.error.js'
);
const { AuthWriteService } = await import(
  '../../dist/authentication/services/authentication-write.service.js'
);
const { AdminWriteService } = await import(
  '../../dist/authentication/services/admin-write.service.js'
);
const { keycloakTenantAttributes, resolveTenantId } = await import(
  '../../dist/authentication/utils/tenant-context.js'
);
const { UserWriteService } = await import(
  '../../dist/authentication/services/user-write.service.js'
);
const { RegisterService } = await import(
  '../../dist/authentication/services/register.service.js'
);

const sink = { debug() {}, info() {}, warn() {}, error() {} };
const logger = { log: () => sink };

test('authentication errors retain canonical request metadata', () => {
  ContextAccessor.run(
    {
      requestId: 'request-auth-1',
      correlationId: 'correlation-auth-1',
      startedAtEpochMs: Date.now(),
      principal: { subject: 'subject-1', actorId: 'actor-1', roles: [] },
      tenant: { tenantId: 'tenant-1', source: 'verified-principal', verified: true },
      client: {},
      transport: { type: 'graphql', operation: 'credentialsLogin' },
      trace: { traceId: 'trace-auth-1', spanId: 'span-auth-1' },
    },
    () => {
      const error = new AuthenticationStateException('invalid-state');
      assert.equal(error.code, 'AUTHENTICATION_STATE_INVALID');
      assert.equal(error.requestId, 'request-auth-1');
      assert.equal(error.correlationId, 'correlation-auth-1');
      assert.equal(error.traceId, 'trace-auth-1');
      assert.equal(error.actorId, 'actor-1');
      assert.equal(error.tenantId, 'tenant-1');
    },
  );
});

test('unknown usernames are mapped to InvalidCredentials without leaking existence', async () => {
  let dummyVerifications = 0;
  const service = new AuthWriteService(
    logger,
    {},
    {},
    {},
    {},
    {},
    {},
    {},
    { findByUsername: async () => { throw new Error('not found'); } },
    {},
    { dummyVerify: async () => { dummyVerifications += 1; } },
    {},
  );

  await assert.rejects(
    service.passwordLogin({ username: 'missing', password: 'secret' }),
    (error) => error instanceof InvalidCredentialsException && error.code === 'INVALID_CREDENTIALS',
  );
  assert.equal(dummyVerifications, 1);
});

test('user deletion awaits every downstream event and uses idempotent local deletion', async () => {
  const sent = [];
  const service = new AdminWriteService(
    logger,
    {},
    {},
    {},
    { send: async (event) => { sent.push(event); } },
    { authUser: { deleteMany: async ({ where }) => ({ count: where.id === 'user-1' ? 1 : 0 }) } },
  );
  service.kcRequest = async () => undefined;

  await service.deleteUser('user-1', 'actor-1');

  assert.equal(sent.length, 6);
  assert.deepEqual(new Set(sent.map(({ payload }) => payload.userId)), new Set(['user-1']));
  assert.ok(sent.every(({ meta }) => meta.actorId === 'actor-1'));
});

test('tenant resolution prefers an explicit verified UUID and rejects invalid values', () => {
  const tenantId = '00000000-0000-4000-8000-000000000005';

  assert.equal(resolveTenantId(tenantId), tenantId);
  assert.deepEqual(keycloakTenantAttributes(tenantId), { tenants: [tenantId] });
  assert.throws(
    () => resolveTenantId('not-a-uuid'),
    (error) =>
      error instanceof AuthenticationStateException &&
      error.code === 'AUTHENTICATION_STATE_INVALID',
  );
});

test('guest and OAuth Keycloak users receive tenant attributes', async () => {
  const tenantId = '00000000-0000-4000-8000-000000000005';
  const requests = [];
  const service = new UserWriteService(
    logger,
    {},
    {},
    { async assignRealmRoleToUser() {} },
    {},
    { async send() {} },
    {},
    {},
    { authUser: { async create() {} } },
    { async schedule() {} },
    {},
  );
  service.createUsernameAndEmailAndPassword = async () => ({
    username: 'ada',
    email: 'ada@example.com',
    password: 'secret',
  });
  service.findUserIdByUsername = async () => '00000000-0000-4000-8000-000000000006';
  service.adminJsonHeaders = async () => ({});
  service.kcRequest = async (_method, _path, request) => {
    requests.push(request.data);
  };

  await service.createGuestUser({
    firstName: 'Ada',
    lastName: 'Lovelace',
    eventEndsAt: new Date(Date.now() + 60_000),
    tenantId,
  });
  assert.deepEqual(requests[0].attributes, { tenants: [tenantId] });

  await ContextAccessor.run(
    {
      tenant: { tenantId, source: 'verified-principal', verified: true },
    },
    () =>
      service.createKeycloakUser({
        provider: 'github',
        providerId: 'provider-1',
        email: 'ada@example.com',
      }),
  );
  assert.deepEqual(requests[1].attributes.tenants, [tenantId]);
  assert.equal(requests[1].attributes.provider, 'github');
});

test('standard and admin Keycloak sign-up receive tenant attributes', async () => {
  const tenantId = '00000000-0000-4000-8000-000000000005';
  const requests = [];
  const register = new RegisterService(
    logger,
    {},
    {},
    {},
    { async assignRealmRoleToUser() {} },
    {},
    {},
    {},
  );
  register.adminJsonHeaders = async () => ({});
  register.kcRequest = async (_method, _path, request) => {
    requests.push(request.data);
  };
  register.findUserIdByUsername = async () => undefined;

  const admin = new AdminWriteService(logger, {}, {}, {}, {}, {});
  admin.adminJsonHeaders = async () => ({});
  admin.kcRequest = async (_method, _path, request) => {
    requests.push(request.data);
  };
  admin.findUserIdByUsername = async () => undefined;

  await ContextAccessor.run(
    {
      tenant: { tenantId, source: 'verified-principal', verified: true },
    },
    async () => {
      await assert.rejects(
        register.signUp(
          {
            id: 'pending-user',
            username: 'ada',
            firstName: 'Ada',
            lastName: 'Lovelace',
            email: 'ada@example.com',
            password: 'secret',
          },
          'token',
        ),
      );
      await assert.rejects(
        admin.adminSignUp({
          username: 'admin',
          firstName: 'Admin',
          lastName: 'User',
          email: 'admin@example.com',
          password: 'secret',
        }),
      );
    },
  );

  assert.deepEqual(requests[0].attributes, { tenants: [tenantId] });
  assert.deepEqual(requests[1].attributes, { tenants: [tenantId] });
});

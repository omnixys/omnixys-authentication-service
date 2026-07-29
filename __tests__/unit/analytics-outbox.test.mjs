import assert from 'node:assert/strict';
import test from 'node:test';
import 'reflect-metadata';

const { ContextAccessor } = await import('@omnixys/context');
const { AnalyticsOutboxService } = await import(
  '../../dist/analytics/analytics-outbox.service.js'
);

const verifiedContext = {
  requestId: 'request-auth-outbox-1',
  correlationId: 'correlation-auth-outbox-1',
  startedAtEpochMs: Date.now(),
  principal: { subject: 'user-1', actorId: 'user-1', roles: [] },
  tenant: {
    tenantId: '11111111-1111-4111-8111-111111111111',
    source: 'verified-principal',
    verified: true,
  },
  client: {},
  transport: { type: 'graphql', operation: 'credentialsLogin' },
  trace: {},
};

test('authentication facts retain the idempotent outbox id and verified context', async () => {
  const writes = [];
  const transaction = {
    analyticsOutbox: {
      create: async (input) => {
        writes.push(input);
        return { id: 'outbox-1', ...input.data };
      },
    },
  };

  await ContextAccessor.run(verifiedContext, () =>
    new AnalyticsOutboxService().enqueue(
      transaction,
      'authentication.login.succeeded.v1',
      {
        eventName: 'LoginSucceeded',
        aggregateId: 'login-1',
        aggregateType: 'login-attempt',
        subjectId: 'user-1',
        properties: { method: 'password' },
      },
    ),
  );

  assert.equal(writes.length, 1);
  assert.equal(writes[0].data.tenantId, verifiedContext.tenant.tenantId);
  assert.equal(writes[0].data.correlationId, verifiedContext.correlationId);
  assert.equal(writes[0].data.actorId, 'user-1');
  assert.equal(writes[0].data.payload.producer, 'authentication');
  assert.equal(writes[0].data.payload.eventName, 'LoginSucceeded');
});

test('authentication facts reject sensitive properties before persistence', async () => {
  const transaction = {
    analyticsOutbox: { create: async () => assert.fail('must not persist') },
  };

  await assert.rejects(
    ContextAccessor.run(verifiedContext, () =>
      new AnalyticsOutboxService().enqueue(
        transaction,
        'authentication.login.failed.v1',
        {
          eventName: 'LoginFailed',
          aggregateId: 'login-2',
          aggregateType: 'login-attempt',
          properties: { accessToken: 'secret' },
        },
      ),
    ),
  );
});

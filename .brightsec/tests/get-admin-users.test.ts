import { test, before, after } from 'node:test';
import { SecRunner } from '@sectester/runner';
import { Severity, AttackParamLocation, HttpMethod } from '@sectester/scan';

const timeout = 40 * 60 * 1000;
const signal = AbortSignal.timeout(timeout);
const baseUrl = process.env.BRIGHT_TARGET_URL!;

let runner!: SecRunner;

before(async c => {
  c.diagnostic(`${new Date().toJSON()} Initializing SecRunner...`)

  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME!,
    projectId: process.env.BRIGHT_PROJECT_ID!
  });



  await runner.init();

  c.diagnostic(`${new Date().toJSON()} SecRunner initialized`);
}, {
  signal
});

after(async c => {
  c.diagnostic(`${new Date().toJSON()} Clearing SecRunner...`);
  await runner.clear()
  c.diagnostic(`${new Date().toJSON()} SecRunner cleared`);
}, {
  signal
});

test('GET /admin/users', { signal }, async t => {
  t.diagnostic(`${new Date().toJSON()} Scanning GET /admin/users...`);

  await runner
    .createScan({
      tests: ['bopla', 'xss', 'csrf'],
      attackParamLocations: [AttackParamLocation.QUERY, AttackParamLocation.HEADER]
    })
    .threshold(Severity.CRITICAL)
    .timeout(timeout)
    .run({
      method: HttpMethod.GET,
      url: `${baseUrl}/admin/users`,
      auth: process.env.BRIGHT_AUTH_ID
    });

  t.diagnostic(`${new Date().toJSON()} GET /admin/users scan completed`);
});

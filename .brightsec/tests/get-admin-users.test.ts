import { test, before, after } from 'node:test';
import { SecRunner } from '@sectester/runner';
import { Severity, AttackParamLocation, HttpMethod } from '@sectester/scan';

console.time('GET /admin/users');
const timeout = 40 * 60 * 1000;
const baseUrl = process.env.BRIGHT_TARGET_URL!;

let runner!: SecRunner;

before(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME!,
    projectId: process.env.BRIGHT_PROJECT_ID!
  });

  await runner.init();
});

after(() => runner.clear());

const signal = AbortSignal.timeout(timeout);
signal.addEventListener('abort', () => {
  console.timeEnd('GET /admin/users');
  console.log('Test aborted due to timeout', signal.reason);
}, {
    once: true
});

test('GET /admin/users', { signal }, async () => {
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
});

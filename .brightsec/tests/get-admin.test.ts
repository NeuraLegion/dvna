import { test, before, after } from 'node:test';
import { Severity, AttackParamLocation, HttpMethod } from '@sectester/scan';
import { SecRunner } from '@sectester/runner';

let runner!: SecRunner;

const timeout = 40 * 60 * 1000; // 40 minutes
const baseUrl = process.env.BRIGHT_TARGET_URL!;

before(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME!,
    projectId: process.env.BRIGHT_PROJECT_ID!
  });

  await runner.init();
});

after(() => runner.clear());

// Test for GET /admin endpoint

test('GET /admin', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['csrf', 'xss', 'bopla', 'full_path_disclosure'],
      attackParamLocations: [AttackParamLocation.HEADER, AttackParamLocation.PATH, AttackParamLocation.QUERY]
    })
    .threshold(Severity.CRITICAL)
    .timeout(timeout)
    .run({
      method: HttpMethod.GET,
      url: `${baseUrl}/admin`,
      auth: process.env.BRIGHT_AUTH_ID
    });
});

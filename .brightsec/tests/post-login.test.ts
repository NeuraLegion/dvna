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

// Test for POST /login endpoint

test('POST /login', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['csrf', 'sqli'],
      attackParamLocations: [AttackParamLocation.BODY],
      skipStaticParams: false // Not required for this test
    })
    .threshold(Severity.CRITICAL)
    .timeout(timeout)
    .run({
      method: HttpMethod.POST,
      url: `${baseUrl}/login`,
      body: {
        username: "user",
        password: "pass"
      },
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      auth: process.env.BRIGHT_AUTH_ID
    });
});

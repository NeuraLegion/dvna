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

// Test case for POST /app/ping

test('POST /app/ping', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['osi', 'csrf', 'xss', 'unvalidated_redirect'],
      attackParamLocations: [AttackParamLocation.BODY],
      skipStaticParams: false // Only relevant for date_manipulation, but set to false as per rule
    })
    .threshold(Severity.CRITICAL)
    .timeout(timeout)
    .run({
      method: HttpMethod.POST,
      url: `${baseUrl}/app/ping`,
      body: {
        ping: "ping"
      },
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      auth: process.env.BRIGHT_AUTH_ID // Assuming authentication is required
    });
});

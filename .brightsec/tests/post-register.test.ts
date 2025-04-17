import { test, before, after } from 'node:test';
import { Severity, AttackParamLocation, HttpMethod } from '@sectester/scan';
// Other setup and teardown logic from the test skeleton

const timeout = 40 * 60 * 1000;
const baseUrl = process.env.BRIGHT_TARGET_URL!;

// Test for POST /register

test('POST /register', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['csrf', 'sqli', 'xss', 'email_injection'],
      attackParamLocations: [AttackParamLocation.BODY]
    })
    .threshold(Severity.CRITICAL)
    .timeout(timeout)
    .run({
      method: HttpMethod.POST,
      url: `${baseUrl}/register`,
      body: {
        username: "exampleUser",
        password: "examplePass",
        email: "example@email.com"
      },
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });
});

import { test, before, after } from 'node:test';
import { Severity, AttackParamLocation, HttpMethod } from '@sectester/scan';
// Other setup and teardown logic from the test skeleton

const timeout = 40 * 60 * 1000;
const baseUrl = process.env.BRIGHT_TARGET_URL!;

// Test for POST /register endpoint

test('POST /register', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['csrf', 'sqli', 'business_constraint_bypass'],
      attackParamLocations: [AttackParamLocation.BODY]
    })
    .threshold(Severity.CRITICAL)
    .timeout(timeout)
    .run({
      method: HttpMethod.POST,
      url: `${baseUrl}/register`,
      body: {
        username: "newUser",
        password: "newPass"
      },
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });
});
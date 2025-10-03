import { test, before, after } from 'node:test';
import { SecRunner } from '@sectester/runner';
import { AttackParamLocation, HttpMethod } from '@sectester/scan';

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

test('POST /resetpw', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['csrf', 'sqli', 'xss', 'secret_tokens', 'bopla'],
      attackParamLocations: [AttackParamLocation.BODY],
      starMetadata: { databases: ['MySQL'] }
    })
    .setFailFast(false)
    .timeout(timeout)
    .run({
      method: HttpMethod.POST,
      url: `${baseUrl}/resetpw`,
      body: {
        login: 'exampleUser',
        token: '5f4dcc3b5aa765d61d8327deb882cf99',
        password: 'examplePassword123',
        cpassword: 'examplePassword123'
      },
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      auth: process.env.BRIGHT_AUTH_ID
    });
});
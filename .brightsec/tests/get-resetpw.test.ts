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

test('GET /resetpw', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['csrf', 'xss', 'sqli', 'unvalidated_redirect', 'secret_tokens'],
      attackParamLocations: [AttackParamLocation.QUERY],
      starMetadata: {
        code_source: "NeuraLegion/dvna:master",
        databases: ["MySQL"],
        user_roles: {
          roles: ["admin", "user"]
        }
      },
      poolSize: +process.env.SECTESTER_SCAN_POOL_SIZE || undefined
    })
    .setFailFast(false)
    .timeout(timeout)
    .run({
      method: HttpMethod.GET,
      url: `${baseUrl}/resetpw?login=exampleUser&token=5f4dcc3b5aa765d61d8327deb882cf99`,
      auth: process.env.BRIGHT_AUTH_ID
    });
});
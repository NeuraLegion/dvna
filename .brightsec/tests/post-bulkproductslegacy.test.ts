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

test('POST /bulkproductslegacy', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['file_upload', 'proto_pollution', 'stored_xss', 'sqli', 'xxe'],
      attackParamLocations: [AttackParamLocation.BODY],
      starMetadata: { databases: ['MySQL'] }
    })
    .setFailFast(false)
    .timeout(timeout)
    .run({
      method: HttpMethod.POST,
      url: `${baseUrl}/bulkproductslegacy`,
      headers: { 'Content-Type': 'multipart/form-data' },
      body: `--boundary\r\nContent-Disposition: form-data; name="products"; filename="products.txt"\r\nContent-Type: text/plain\r\n\r\n[{"name":"Product1","code":"P001","tags":"tag1,tag2","description":"Description of Product1"}]\r\n--boundary--`,
      auth: process.env.BRIGHT_AUTH_ID
    });
});
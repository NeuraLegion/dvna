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

test('POST /app/bulkproducts', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['xxe', 'file_upload', 'stored_xss', 'csrf'],
      attackParamLocations: [AttackParamLocation.BODY],
      starMetadata: { databases: ['MySQL'] }
    })
    .setFailFast(false)
    .timeout(timeout)
    .run({
      method: HttpMethod.POST,
      url: `${baseUrl}/app/bulkproducts`,
      headers: { 'Content-Type': 'multipart/form-data' },
      body: `--boundary\r\nContent-Disposition: form-data; name="products"; filename="products.xml"\r\nContent-Type: text/xml\r\n\r\n<products>\n  <product>\n    <name>Sample Product</name>\n    <code>SP001</code>\n    <tags>sample, test</tags>\n    <description>This is a sample product description.</description>\n  </product>\n</products>\r\n--boundary--`,
      auth: process.env.BRIGHT_AUTH_ID
    });
});
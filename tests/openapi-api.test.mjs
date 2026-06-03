import test, { before } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

const projectRoot = process.cwd();
const envFilePath = path.join(projectRoot, '.env.test');
const baseUrl = process.env.API_BASE_URL ?? 'https://proxiedmail.com';

function loadDotEnv(filePath) {
  const content = fs.readFileSync(filePath, 'utf8');
  const entries = {};

  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) {
      continue;
    }

    const separatorIndex = line.indexOf('=');
    if (separatorIndex === -1) {
      continue;
    }

    const key = line.slice(0, separatorIndex).trim();
    let value = line.slice(separatorIndex + 1).trim();

    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }

    entries[key] = value;
  }

  return entries;
}

function getJson(response) {
  const contentType = response.headers.get('content-type') ?? '';
  assert.match(
    contentType,
    /application\/(?:json|vnd\.api\+json)/i,
    `Expected JSON response but received content-type: ${contentType || 'missing'}`,
  );

  return response.json();
}

const env = loadDotEnv(envFilePath);
const username = process.env.E2E_USERNAME ?? env.E2E_USERNAME;
const password = process.env.E2E_PASSWORD ?? env.E2E_PASSWORD;

assert.ok(username, 'E2E_USERNAME is required');
assert.ok(password, 'E2E_PASSWORD is required');

let bearerToken;
let apiToken;

before(async () => {
  const authResponse = await fetch(`${baseUrl}/api/v1/auth`, {
    method: 'POST',
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      data: {
        type: 'auth-request',
        attributes: {
          username,
          password,
        },
      },
    }),
  });

  assert.equal(authResponse.status, 200, 'POST /api/v1/auth should succeed');
  const authJson = await getJson(authResponse);
  bearerToken = authJson?.data?.attributes?.token;
  assert.equal(typeof bearerToken, 'string');
  assert.ok(bearerToken.length > 0, 'Bearer token should not be empty');

  const apiTokenResponse = await fetch(`${baseUrl}/api/v1/api-token`, {
    headers: {
      Accept: 'application/json',
      Authorization: `Bearer ${bearerToken}`,
    },
  });

  assert.equal(apiTokenResponse.status, 200, 'GET /api/v1/api-token should succeed');
  const apiTokenJson = await getJson(apiTokenResponse);
  apiToken = apiTokenJson?.token;
  assert.equal(typeof apiToken, 'string');
  assert.ok(apiToken.length > 0, 'API token should not be empty');
});

test('POST /api/v1/auth returns the documented OAuth token envelope', async () => {
  const authResponse = await fetch(`${baseUrl}/api/v1/auth`, {
    method: 'POST',
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      data: {
        type: 'auth-request',
        attributes: {
          username,
          password,
        },
      },
    }),
  });

  assert.equal(authResponse.status, 200);
  const body = await getJson(authResponse);

  assert.equal(body?.data?.type, 'oauth-access-tokens');
  assert.equal(typeof body?.data?.id, 'string');
  assert.equal(typeof body?.data?.attributes?.token, 'string');
  assert.equal(typeof body?.data?.attributes?.expires_at, 'string');
});

test('GET /api/v1/api-token returns a long-lived API token', async () => {
  const response = await fetch(`${baseUrl}/api/v1/api-token`, {
    headers: {
      Accept: 'application/json',
      Authorization: `Bearer ${bearerToken}`,
    },
  });

  assert.equal(response.status, 200);
  const body = await getJson(response);

  assert.equal(typeof body?.token, 'string');
  assert.ok(body.token.length > 0, 'API token should not be empty');
});

test('GET /api/v1/users/me accepts the documented Token header', async () => {
  const response = await fetch(`${baseUrl}/api/v1/users/me`, {
    headers: {
      Accept: 'application/json',
      Token: apiToken,
    },
  });

  assert.equal(response.status, 200);
  const body = await getJson(response);

  assert.equal(typeof body?.data?.id, 'string');
  assert.equal(typeof body?.data?.attributes?.username, 'string');
  assert.equal(typeof body?.meta?.plan?.isPaid, 'boolean');
});

test('GET /api/v1/proxy-bindings returns the documented collection envelope', async () => {
  const response = await fetch(`${baseUrl}/api/v1/proxy-bindings?sort=desc`, {
    headers: {
      Accept: 'application/json',
      Token: apiToken,
    },
  });

  assert.equal(response.status, 200);
  const body = await getJson(response);

  assert.ok(Array.isArray(body?.data), 'data should be an array');
  assert.equal(typeof body?.meta?.usedProxyBindings, 'number');
  assert.equal(typeof body?.meta?.availableProxyBindings, 'number');
});
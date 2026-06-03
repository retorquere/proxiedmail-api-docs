import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
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

function decodeBase32(input) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const normalized = input.toUpperCase().replace(/=+$/g, '').replace(/\s+/g, '');
  let bits = '';

  for (const char of normalized) {
    const index = alphabet.indexOf(char);
    if (index === -1) {
      throw new Error(`Invalid base32 character: ${char}`);
    }
    bits += index.toString(2).padStart(5, '0');
  }

  const bytes = [];
  for (let offset = 0; offset + 8 <= bits.length; offset += 8) {
    bytes.push(Number.parseInt(bits.slice(offset, offset + 8), 2));
  }

  return Buffer.from(bytes);
}

function generateTotp(secret, timeStep = 30, digits = 6) {
  const counter = Math.floor(Date.now() / 1000 / timeStep);
  const buffer = Buffer.alloc(8);
  buffer.writeBigUInt64BE(BigInt(counter));

  const hmac = crypto.createHmac('sha1', decodeBase32(secret)).update(buffer).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binary =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  return String(binary % 10 ** digits).padStart(digits, '0');
}

async function parseResponse(response) {
  const contentType = response.headers.get('content-type') ?? '';
  const text = await response.text();
  let body = text;

  if (/application\/(?:json|vnd\.api\+json)/i.test(contentType) && text) {
    body = JSON.parse(text);
  }

  return {
    status: response.status,
    contentType,
    body,
    headers: response.headers,
  };
}

function assertJsonResponse(result) {
  assert.match(
    result.contentType,
    /application\/(?:json|vnd\.api\+json)/i,
    `Expected JSON response but received content-type: ${result.contentType || 'missing'}`,
  );
}

function assertClientError(result, message) {
  assert.ok(result.status >= 400 && result.status < 500, `${message}. Received status ${result.status}`);
}

function extractDomain(entry) {
  if (typeof entry === 'string') {
    return entry;
  }

  if (entry && typeof entry.domain === 'string') {
    return entry.domain;
  }

  return null;
}

function randomString(prefix) {
  return `${prefix}-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
}

const env = loadDotEnv(envFilePath);
const username = process.env.E2E_USERNAME ?? env.E2E_USERNAME;
const password = process.env.E2E_PASSWORD ?? env.E2E_PASSWORD;

assert.ok(username, 'E2E_USERNAME is required');
assert.ok(password, 'E2E_PASSWORD is required');

const state = {
  bearerToken: null,
  apiToken: null,
  me: null,
  bindings: [],
  realEmails: [],
  verifiedEmails: [],
  settings: [],
  availableDomains: [],
};

async function request(pathname, { method = 'GET', auth = 'token', headers = {}, body, formData } = {}) {
  const requestHeaders = { Accept: 'application/json', ...headers };
  const effectiveAuth = auth === 'token' && pathname.startsWith('/gapi/') ? 'bearer' : auth;

  if (effectiveAuth === 'token') {
    requestHeaders.Token = state.apiToken;
  } else if (effectiveAuth === 'bearer') {
    requestHeaders.Authorization = `Bearer ${state.bearerToken}`;
  }

  const init = { method, headers: requestHeaders };

  if (body !== undefined) {
    init.body = JSON.stringify(body);
    init.headers['Content-Type'] = 'application/json';
  }

  if (formData) {
    init.body = formData;
    delete init.headers['Content-Type'];
  }

  const response = await fetch(`${baseUrl}${pathname}`, init);
  return parseResponse(response);
}

before(async () => {
  const authResponse = await request('/api/v1/auth', {
    method: 'POST',
    auth: 'none',
    body: {
      data: {
        type: 'auth-request',
        attributes: { username, password },
      },
    },
  });

  assert.equal(authResponse.status, 200, 'POST /api/v1/auth should succeed');
  assertJsonResponse(authResponse);
  state.bearerToken = authResponse.body?.data?.attributes?.token;
  assert.equal(typeof state.bearerToken, 'string');

  const apiTokenResponse = await request('/api/v1/api-token', { auth: 'bearer' });
  assert.equal(apiTokenResponse.status, 200, 'GET /api/v1/api-token should succeed');
  assertJsonResponse(apiTokenResponse);
  state.apiToken = apiTokenResponse.body?.token;
  assert.equal(typeof state.apiToken, 'string');

  const [meResult, bindingsResult, realEmailsResult, verifiedEmailsResult, settingsResult, domainsResult] = await Promise.all([
    request('/api/v1/users/me'),
    request('/api/v1/proxy-bindings?sort=desc'),
    request('/gapi/real-emails'),
    request('/gapi/verified-emails-list'),
    request('/gapi/settings'),
    request('/gapi/available-domains'),
  ]);

  assert.equal(meResult.status, 200);
  assert.equal(bindingsResult.status, 200);
  assert.equal(realEmailsResult.status, 200);
  assert.equal(verifiedEmailsResult.status, 200);
  assert.equal(settingsResult.status, 200);
  assert.equal(domainsResult.status, 200);

  state.me = meResult.body;
  state.bindings = bindingsResult.body?.data ?? [];
  state.realEmails = realEmailsResult.body?.data ?? [];
  state.verifiedEmails = verifiedEmailsResult.body?.List ?? [];
  state.settings = settingsResult.body ?? [];
  state.availableDomains = domainsResult.body ?? [];
});

after(async () => {});

test('POST /api/v1/auth returns the documented OAuth token envelope', async () => {
  const result = await request('/api/v1/auth', {
    method: 'POST',
    auth: 'none',
    body: {
      data: {
        type: 'auth-request',
        attributes: { username, password },
      },
    },
  });

  assert.equal(result.status, 200);
  assertJsonResponse(result);
  assert.equal(result.body?.data?.type, 'oauth-access-tokens');
  assert.equal(typeof result.body?.data?.id, 'string');
  assert.equal(typeof result.body?.data?.attributes?.token, 'string');
  assert.equal(typeof result.body?.data?.attributes?.expires_at, 'string');
});

test('GET /api/v1/api-token returns a long-lived API token', async () => {
  const result = await request('/api/v1/api-token', { auth: 'bearer' });

  assert.equal(result.status, 200);
  assertJsonResponse(result);
  assert.equal(typeof result.body?.token, 'string');
  assert.ok(result.body.token.length > 0, 'API token should not be empty');
});

test('authenticated read endpoints return JSON payloads', async () => {
  const results = await Promise.all([
    request('/api/v1/users/me?updateFrontCache=0'),
    request('/api/v1/users/allow-microsoft-domains'),
    request('/api/v1/product-tips'),
    request('/api/v1/proxy-bindings?sort=desc'),
    request('/gapi/available-domains'),
    request('/gapi/custom-domains?ignoreProcessing=1'),
    request('/gapi/settings'),
    request('/gapi/passwords'),
    request('/gapi/used-on'),
    request('/gapi/real-emails'),
    request('/gapi/verified-emails-list'),
  ]);

  for (const result of results) {
    assert.equal(result.status, 200);
    assertJsonResponse(result);
  }

  const [meResult, microsoftResult, productTipsResult, bindingsResult] = results;
  assert.equal(typeof meResult.body?.data?.id, 'string');
  assert.equal(typeof microsoftResult.body?.status, 'boolean');
  assert.ok(Array.isArray(productTipsResult.body), 'Product tips should be an array');
  assert.ok(Array.isArray(bindingsResult.body?.data), 'Proxy bindings should be an array');
});

test('POST /api/v1/stat-events accepts a basic analytics event', async () => {
  const result = await request('/api/v1/stat-events', {
    method: 'POST',
    auth: 'none',
    body: { event: randomString('copilot-openapi-event') },
  });

  assert.ok([200, 201].includes(result.status), `Unexpected status ${result.status}`);
  assertJsonResponse(result);
});

test('binding-related endpoints are exercised without leaving residual data', async () => {
  const existingBinding = state.bindings[0];
  assert.ok(existingBinding, 'Expected an existing binding on the test account');

  const createResult = await request('/api/v1/proxy-bindings', {
    method: 'POST',
    body: {
      data: {
        type: 'proxy_bindings',
        attributes: {
          real_addresses: [state.realEmails[0]?.email ?? username],
          proxy_address: `${randomString('copilot-openapi')}@${state.availableDomains.map(extractDomain).find(Boolean) ?? 'proxiedmail.com'}`,
          is_browsable: false,
          wildcard_auto_create: false,
        },
      },
    },
  });
  assert.equal(createResult.status, 500);
  assert.match(createResult.body?.data?.attributes?.message ?? '', /paywall-use-same-real-address/i);

  const patchResult = await request(`/api/v1/proxy-bindings/${existingBinding.id}`, {
    method: 'PATCH',
    body: {
      data: {
        id: existingBinding.id,
        type: 'proxy_bindings',
        attributes: {
          proxy_address: existingBinding.attributes.proxy_address,
          description: existingBinding.attributes.description,
          wildcard_auto_create: Boolean(existingBinding.attributes.wildcard_auto_create_on),
        },
      },
    },
  });
  assert.equal(patchResult.status, 200);
  assert.equal(patchResult.body?.data?.id, existingBinding.id);

  const contactsList = await request(`/api/v1/proxy-bindings/${existingBinding.id}/contacts`);
  assert.equal(contactsList.status, 200);
  assert.ok(Array.isArray(contactsList.body?.data), 'Contacts response should be an array');

  const bogusBindingId = 'D2162694-1000-0000-000000000000';

  const createContactResult = await request('/api/v1/contacts', {
    method: 'POST',
    body: {
      data: {
        type: 'proxy_binding_contacts',
        attributes: {
          recipient_email: 'bogus@example.net',
        },
        relationships: {
          proxy_binding: {
            data: {
              type: 'proxy_bindings',
              id: bogusBindingId,
            },
          },
        },
      },
    },
  });
  assert.equal(createContactResult.status, 404);

  const passwordResult = await request('/gapi/passwords/proxy-binding', {
    method: 'PATCH',
    body: {
      proxy_binding_id: bogusBindingId,
      password: randomString('copilot-password'),
    },
  });
  assert.equal(passwordResult.status, 422);

  const usedOnUpdate = await request('/gapi/used-on', {
    method: 'PATCH',
    body: {
      proxy_binding_id: bogusBindingId,
      list: ['copilot-openapi-suite'],
    },
  });
  assert.equal(usedOnUpdate.status, 422);

  const reverseLookup = await request('/gapi/proxy-binding/reverse-lookup?reverseAddress=bogus@example.net');
  assert.equal(reverseLookup.status, 404);

  const deleteResult = await request(`/api/v1/proxy-bindings/${bogusBindingId}`, { method: 'DELETE' });
  assert.equal(deleteResult.status, 500);
});

test('PATCH /gapi/settings/update accepts the current settings payload', async () => {
  const result = await request('/gapi/settings/update', {
    method: 'PATCH',
    body: {
      settings: state.settings,
    },
  });

  assert.equal(result.status, 200);
  assertJsonResponse(result);
});

test('POST /api/v1/users currently fails validation without captcha input', async () => {
  const result = await request('/api/v1/users', {
    method: 'POST',
    auth: 'none',
    body: {
      data: {
        type: 'users',
        attributes: {
          username: `${randomString('copilot-user')}@example.test`,
          password: randomString('Secret123!'),
          keyLandingPage: 'api-docs-test',
          v: '1',
        },
      },
    },
  });

  assert.equal(result.status, 422);
  assertJsonResponse(result);
  assert.match(result.body?.data?.attributes?.message ?? '', /captcha/i);
});

test('Google 2FA endpoints are exercised and remove-2fa is safe to call afterward', async () => {
  const startResult = await request('/api/v1/2fa-google', {
    method: 'POST',
    body: {
      data: {
        type: 'users_2fa',
        attributes: {
          email: username,
          type_2fa: 2,
        },
      },
    },
  });

  assert.equal(startResult.status, 200);
  assert.equal(typeof startResult.body?.secret, 'string');
  assert.equal(typeof startResult.body?.qr_url, 'string');

  const confirmResult = await request('/api/v1/confirm-google', {
    method: 'POST',
    body: {
      data: {
        code: generateTotp(startResult.body.secret),
      },
    },
  });

  assert.equal(confirmResult.status, 500);
  assert.match(confirmResult.body?.data?.attributes?.message ?? '', /confirmAuthenticatorCode\(\) must be of the type string, null given/i);

  const removeResult = await request('/api/v1/users/remove-2fa', { method: 'DELETE' });
  assert.ok([200, 204].includes(removeResult.status), `Unexpected status ${removeResult.status}`);
});

test('validation-only endpoints are exercised without sending real mail or SMS', async () => {
  const resendConfirmation = await request('/api/v1/resend-confirmation', {
    method: 'POST',
    body: {
      data: {
        type: 'confirmation',
        attributes: {},
      },
    },
  });

  const emailReplace = await request('/api/v1/emails/replace', {
    method: 'POST',
    body: {
      data: {
        type: 'replace-real-emails',
        attributes: {
          oldEmail: 'missing@example.test',
          newEmail: 'replacement@example.test',
        },
      },
    },
  });

  const startSms = await request('/api/v1/2fa-sms', {
    method: 'POST',
    body: {
      data: {
        type: 'users_2fa',
        attributes: {
          type_2fa: 1,
        },
      },
    },
  });

  const confirmSms = await request('/api/v1/confirm-sms', {
    method: 'POST',
    body: {
      data: {
        code: '000000',
      },
    },
  });

  const askFormData = new FormData();
  askFormData.set('name', 'Copilot Test');
  askFormData.set('email', 'noreply@example.test');
  const askForm = await request('/api/v1/ask-form', {
    method: 'POST',
    auth: 'none',
    formData: askFormData,
  });

  assert.equal(resendConfirmation.status, 500);
  assert.match(resendConfirmation.body?.data?.attributes?.message ?? '', /undefined index: email/i);
  assert.equal(emailReplace.status, 200);
  assert.equal(emailReplace.body?.data?.attributes?.status, false);
  assert.equal(startSms.status, 500);
  assert.match(startSms.body?.data?.attributes?.message ?? '', /must be of the type string, null given/i);
  assert.equal(confirmSms.status, 500);
  assert.match(confirmSms.body?.data?.attributes?.message ?? '', /confirmSmsCode\(\) must be of the type string, null given/i);
  assertClientError(askForm, 'Expected ask-form validation to fail without a message');
});

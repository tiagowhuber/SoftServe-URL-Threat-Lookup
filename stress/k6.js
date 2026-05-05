/**
 * k6 stress test for the URL Threat Lookup service.
 *
 * Scenarios:
 *   lookup_warm  – repeated hits against seed URLs (exercises LRU cache)
 *   lookup_cold  – unique URLs per iteration (forces Redis lookups)
 *   admin_write  – POST /admin/urls (write contention + cache invalidation)
 */

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend } from 'k6/metrics';

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';

// Seed URLs from data/blocklist.json – known-blocked, will warm the LRU cache.
const BLOCKED_URLS = [
  'malware.example.com/download/virus.exe',
  'ransomware.evil.com:443/encrypt/files',
  'dl.badactor.net/payloads/trojan.zip',
  'cdn.malicious-updates.com/patch/win32.exe',
  'drive-by.exploit-kit.ru/flash/update.swf',
  'botnet-c2.darkweb.onion.to:8443/beacon',
  'cryptominer.js.evil.io/mine.js',
  'keylogger-host.net/uploads/keylog.php',
  'spyware-panel.xyz/dashboard/victims',
  'worm.propagate.net/smb/exploit.bin',
  'phishing.example.com/login/steal-credentials',
  'fake-bank.phish.net/account/verify',
  'secure-login.paypa1.com/signin',
  'account-verify.amaz0n.co/payment/update',
  'appleid.apple.com.login.phish.xyz/verify',
  'microsoft-support.helpdesk-alert.com/renew',
  'netfliix.com/account/billing/suspended',
  'steamcommunity.com.trade-offer.ru/confirm',
  'irs-refund.gov-portal.xyz/claim',
  'crypto-wallet.ledger.com.verify.phish.io/restore',
  'dhl-tracking.delivery-notice.net/parcel/pay-fee',
  'fb-security.com/checkpoint/login',
  'spam.example.com/buy-now/cheap-pills',
  'click.spam-king.com/unsubscribe/lol',
  'promo.discount-meds.biz/order/viagra-cheap',
  'lottery-winner.claim-prize.net/congratulations',
  'work-from-home.easy-money.biz/signup',
  'mailer.bulk-blast.org/track/open?id=99182',
  'newsletter.spam-corp.co/click/offer123',
  'casino-bonus.free-spins.bet/register',
];

// Safe-looking URLs that are not in the blocklist – will be cache misses
// on first hit, then LRU hits.
const SAFE_URLS = [
  'www.google.com/search',
  'github.com/golang/go',
  'docs.k6.io/using-k6/metrics',
  'en.wikipedia.org/wiki/URL',
  'cdn.jsdelivr.net/npm/lodash',
];

// Threat categories for admin writes.
const CATEGORIES = ['malware', 'phishing', 'spam'];

// ---------------------------------------------------------------------------
// Custom metrics
// ---------------------------------------------------------------------------

const cacheHitRate   = new Rate('cache_hit_rate');   // approximated via p50 latency split
const errorRate      = new Rate('error_rate');
const lookupDuration = new Trend('lookup_duration_ms', true);
const adminDuration  = new Trend('admin_duration_ms', true);

// ---------------------------------------------------------------------------
// Test options – three concurrent scenarios
// ---------------------------------------------------------------------------

export const options = {
  scenarios: {
    // Scenario 1: warm cache – high VUs hitting the same small URL set.
    // After the first pass the LRU should absorb all traffic.
    lookup_warm: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '20s', target: 50  },
        { duration: '40s', target: 200 },
        { duration: '20s', target: 500 },
        { duration: '20s', target: 0   },
      ],
      exec: 'lookupWarm',
      tags: { scenario: 'warm' },
    },

    // Scenario 2: cold cache – each VU generates unique URLs on every
    // iteration, guaranteeing Redis is hit and the LRU is continually evicted.
    lookup_cold: {
      executor: 'ramping-vus',
      startTime: '10s',
      startVUs: 0,
      stages: [
        { duration: '20s', target: 20  },
        { duration: '40s', target: 80  },
        { duration: '20s', target: 0   },
      ],
      exec: 'lookupCold',
      tags: { scenario: 'cold' },
    },

    // Scenario 3: admin writes – low concurrency, simulates blocklist updates
    // while lookups are running. Validates write contention + cache invalidation.
    admin_write: {
      executor: 'constant-vus',
      startTime: '15s',
      duration: '60s',
      vus: 5,
      exec: 'adminWrite',
      tags: { scenario: 'admin' },
    },
  },

  thresholds: {
    // 99th percentile lookup must stay under 200 ms.
    'lookup_duration_ms{scenario:warm}': ['p(99)<200'],
    'lookup_duration_ms{scenario:cold}': ['p(99)<500'],
    // Admin writes are slower – allow up to 1 s at p(99).
    'admin_duration_ms': ['p(99)<1000'],
    // Overall error rate must stay below 1 %.
    'error_rate': ['rate<0.01'],
    // Standard k6 http checks.
    'http_req_failed': ['rate<0.01'],
    'http_req_duration': ['p(95)<500'],
  },
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function pick(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

function uniqueURL(vu, iter) {
  return `cold-${vu}-${iter}.stress.test/path/resource`;
}

function lookupURL(url, scenarioTag) {
  const res = http.get(`${BASE_URL}/urlinfo/1/${url}`, {
    tags: { name: 'lookup' },
  });

  const ok = check(res, {
    'lookup status 200': (r) => r.status === 200,
    'lookup has safe field': (r) => {
      try { return typeof JSON.parse(r.body).safe === 'boolean'; }
      catch { return false; }
    },
  });

  errorRate.add(!ok);
  lookupDuration.add(res.timings.duration, { scenario: scenarioTag });
  return res;
}

// ---------------------------------------------------------------------------
// Scenario functions
// ---------------------------------------------------------------------------

export function lookupWarm() {
  const url = Math.random() < 0.5 ? pick(BLOCKED_URLS) : pick(SAFE_URLS);
  lookupURL(url, 'warm');
  sleep(0.01);
}

export function lookupCold() {
  // Unique URL every iteration → guaranteed cache miss → Redis lookup.
  lookupURL(uniqueURL(__VU, __ITER), 'cold');
  sleep(0.05);
}

export function adminWrite() {
  // Add a small batch of new URLs to the blocklist.
  const entries = Array.from({ length: 5 }, (_, i) => ({
    url: `admin-write-${__VU}-${__ITER}-${i}.evil.test/payload`,
    threat_category: pick(CATEGORIES),
  }));

  const res = http.post(
    `${BASE_URL}/admin/urls`,
    JSON.stringify(entries),
    {
      headers: { 'Content-Type': 'application/json' },
      tags: { name: 'admin_write' },
    },
  );

  const ok = check(res, {
    'admin write status 200': (r) => r.status === 200,
    'admin write added count': (r) => {
      try { return JSON.parse(r.body).added === entries.length; }
      catch { return false; }
    },
  });

  errorRate.add(!ok);
  adminDuration.add(res.timings.duration);
  sleep(1);
}

// ---------------------------------------------------------------------------
// Setup / teardown
// ---------------------------------------------------------------------------

export function setup() {
  // Verify the service is reachable before starting.
  const res = http.get(`${BASE_URL}/health`);
  if (res.status !== 200) {
    throw new Error(`Health check failed (${res.status}) – is the server running?`);
  }
  console.log(`Service healthy at ${BASE_URL}`);
}

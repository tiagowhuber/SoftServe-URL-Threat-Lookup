/**
 * Read-only stress test — maximize lookup (GET /urlinfo) throughput.
 *
 * Two concurrent scenarios:
 *   warm  – same ~35 seed URLs, exercises LRU cache (expect high hit ratio)
 *   cold  – unique URL per iteration, forces Redis every time (expect low hit ratio)
 */

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend } from 'k6/metrics';

const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';

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
  'spam.example.com/buy-now/cheap-pills',
  'click.spam-king.com/unsubscribe/lol',
  'promo.discount-meds.biz/order/viagra-cheap',
  'lottery-winner.claim-prize.net/congratulations',
  'work-from-home.easy-money.biz/signup',
];

const SAFE_URLS = [
  'www.google.com/search',
  'github.com/golang/go',
  'docs.k6.io/using-k6/metrics',
  'en.wikipedia.org/wiki/URL',
  'cdn.jsdelivr.net/npm/lodash',
];

const errorRate    = new Rate('error_rate');
const readDuration = new Trend('read_duration_ms', true);

export const options = {
  scenarios: {
    warm: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '20s', target: 100  },
        { duration: '40s', target: 500  },
        { duration: '20s', target: 1000 },
        { duration: '20s', target: 0    },
      ],
      exec: 'warmRead',
      tags: { type: 'warm' },
    },
    cold: {
      executor: 'ramping-vus',
      startTime: '10s',
      startVUs: 0,
      stages: [
        { duration: '20s', target: 50  },
        { duration: '40s', target: 200 },
        { duration: '20s', target: 0   },
      ],
      exec: 'coldRead',
      tags: { type: 'cold' },
    },
  },
  thresholds: {
    'read_duration_ms{type:warm}': ['p(99)<200'],
    'read_duration_ms{type:cold}': ['p(99)<500'],
    'error_rate':      ['rate<0.01'],
    'http_req_failed': ['rate<0.01'],
  },
};

function pick(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

export function warmRead() {
  const url = Math.random() < 0.7 ? pick(BLOCKED_URLS) : pick(SAFE_URLS);
  const res = http.get(`${BASE_URL}/urlinfo/1/${url}`);
  const ok = check(res, { 'status 200': r => r.status === 200 });
  errorRate.add(!ok);
  readDuration.add(res.timings.duration, { type: 'warm' });
  sleep(0.01);
}

export function coldRead() {
  const url = `cold-${__VU}-${__ITER}.stress.test/resource`;
  const res = http.get(`${BASE_URL}/urlinfo/1/${url}`);
  const ok = check(res, { 'status 200': r => r.status === 200 });
  errorRate.add(!ok);
  readDuration.add(res.timings.duration, { type: 'cold' });
  sleep(0.05);
}

export function setup() {
  const res = http.get(`${BASE_URL}/health`);
  if (res.status !== 200) throw new Error(`Health check failed (${res.status})`);
  console.log(`Read stress test → ${BASE_URL}`);
}

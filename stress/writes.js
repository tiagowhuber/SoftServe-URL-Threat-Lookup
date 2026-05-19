/**
 * Write-only stress test — maximize blocklist write (POST /admin/urls) throughput.
 *
 * Each VU posts a batch of new URLs as fast as possible.
 * Watch the dashboard: "Writes/sec" and "URLs written/sec" panels.
 * As you add replicas in Phase 2+, writes are bottlenecked by Redis (not the app),
 * so you'll see diminishing returns compared to reads — that's the lesson.
 */

import http from 'k6/http';
import { check } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';

const BASE_URL   = __ENV.BASE_URL   || 'http://localhost:8080';
const BATCH_SIZE = parseInt(__ENV.BATCH_SIZE || '5');

const CATEGORIES = ['malware', 'phishing', 'spam'];

const errorRate    = new Rate('error_rate');
const writeDuration = new Trend('write_duration_ms', true);
const urlsWritten  = new Counter('urls_written_k6');

export const options = {
  scenarios: {
    burst_writes: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '20s', target: 10  },
        { duration: '40s', target: 50  },
        { duration: '20s', target: 100 },
        { duration: '20s', target: 0   },
      ],
    },
  },
  thresholds: {
    'write_duration_ms': ['p(99)<2000'],
    'error_rate':        ['rate<0.01'],
    'http_req_failed':   ['rate<0.01'],
  },
};

function pick(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

export default function () {
  const entries = Array.from({ length: BATCH_SIZE }, (_, i) => ({
    url: `write-${__VU}-${__ITER}-${i}.evil.test/payload`,
    threat_category: pick(CATEGORIES),
  }));

  const res = http.post(
    `${BASE_URL}/admin/urls`,
    JSON.stringify(entries),
    { headers: { 'Content-Type': 'application/json' } },
  );

  const ok = check(res, {
    'status 200': r => r.status === 200,
    'added count matches': r => {
      try { return JSON.parse(r.body).added === entries.length; }
      catch { return false; }
    },
  });

  errorRate.add(!ok);
  writeDuration.add(res.timings.duration);
  if (ok) urlsWritten.add(BATCH_SIZE);
}

export function setup() {
  const res = http.get(`${BASE_URL}/health`);
  if (res.status !== 200) throw new Error(`Health check failed (${res.status})`);
  console.log(`Write stress test → ${BASE_URL}  batch_size=${BATCH_SIZE}`);
}

import http from 'k6/http';
import { sleep, check } from 'k6';

/**
 * Basic k6 test for Whoosh
 * Hits the service on port 2023
 */

export const options = {
    // Number of virtual users
    vus: 10,
    // Duration of the test
    duration: '30s',
    // Success thresholds
    thresholds: {
        http_req_failed: ['rate<0.01'], // fail rate < 1%
        http_req_duration: ['p(95)<500'], // 95% of requests < 500ms
    },
};

const URL = 'http://localhost:2023';

export default function () {
    const res = http.get(URL);

    check(res, {
        'status is 200': (r) => r.status === 200,
    });

    sleep(1);
}

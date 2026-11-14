#!/usr/bin/env python3
"""Record public job started_at, then admit the file lab within a fixed budget.

This is an admission estimate, not a scheduling or cleanup guarantee. GitHub's
350-minute job cap remains authoritative; the lab step has its own 45-minute cap.
Only a fixed-repository GET is used, with the recording step's short-lived,
read-only Actions token. Credentials and authorization headers are never recorded.
"""
import argparse
import contextlib
import datetime as dt
import email.utils
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import sys
import time
import urllib.error
import urllib.request

REPO = 'ena0828/3FS-EC'
JOB = 'native'  # The workflow must keep this unique display name as well.
REF = 'refs/heads/feat/ec-distributed'
API_VERSION = '2026-03-10'
JOB_MINUTES = 350
REQUIRED_MINUTES = 50
LAB_STEP_MINUTES = 45
NANO = 1_000_000_000
MAX_BODY = 2 << 20
REQUEST_SECONDS = 20
DATE_FRESHNESS_SECONDS = 60
RECORD_NAME = 'ec-hosted-job-budget.json'
BODY_NAME = 'ec-hosted-job-budget-api.json'


class GateError(ValueError):
    pass


def require(ok, message):
    if not ok:
        raise GateError(message)


def integer(value, minimum=0):
    return type(value) is int and value >= minimum


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON field')
        result[key] = value
    return result


def parse_json(data):
    value = json.loads(data, object_pairs_hook=unique,
                       parse_constant=lambda _: (_ for _ in ()).throw(GateError('nonfinite JSON')))
    require(type(value) is dict, 'JSON object required')
    return value


def digest(data):
    return hashlib.sha256(data).hexdigest()


def context():
    require(sys.platform == 'linux' and os.getuid() == os.geteuid() == 1001,
            'ordinary hosted Linux UID1001 required')
    expected = {'GITHUB_ACTIONS': 'true', 'RUNNER_OS': 'Linux', 'RUNNER_ENVIRONMENT': 'github-hosted',
                'GITHUB_REPOSITORY': REPO, 'GITHUB_JOB': JOB, 'GITHUB_EVENT_NAME': 'push',
                'GITHUB_REF': REF}
    require(all(os.environ.get(k) == v for k, v in expected.items()), 'unexpected hosted job context')
    run, attempt = (os.environ.get(k, '') for k in ('GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT'))
    require(all(re.fullmatch(r'[1-9][0-9]*', x) for x in (run, attempt)), 'invalid run identity')
    revision, runner = os.environ.get('GITHUB_SHA', ''), os.environ.get('RUNNER_NAME', '')
    require(re.fullmatch(r'[0-9a-f]{40}', revision) is not None and 0 < len(runner) <= 256
            and '\n' not in runner and '\r' not in runner, 'invalid source or runner identity')
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    require(re.fullmatch(r'[0-9a-f-]{36}', boot) is not None, 'invalid boot identity')
    offsets = [line.split() for line in Path('/proc/self/timens_offsets').read_text().splitlines()]
    require(sorted(offsets) == [['boottime', '0', '0'], ['monotonic', '0', '0']],
            'time namespace offsets are unsupported')
    # Only inspect our own namespace; root PID1's namespace link can require
    # ptrace permissions unavailable to the ordinary runner user.
    time_namespace = os.readlink('/proc/self/ns/time')
    require(re.fullmatch(r'time:\[[0-9]+\]', time_namespace) is not None, 'invalid time namespace identity')
    parent = Path(os.environ['RUNNER_TEMP'])
    require(parent.is_absolute() and parent == parent.resolve(strict=True), 'canonical runner temp required')
    info = parent.stat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and not info.st_mode & 0o022,
            'runner temp owner or permissions differ')
    identity = {'repo': REPO, 'run_id': run, 'attempt': attempt, 'head_sha': revision,
                'runner_name': runner, 'job_name': JOB, 'uid': os.getuid(), 'gid': os.getgid(),
                'boot_id': boot, 'time_namespace': time_namespace}
    return parent, identity


def clock():
    # BOOTTIME is a suspend-aware monotonic delta, NOT an estimate from boot age.
    return time.clock_gettime_ns(time.CLOCK_BOOTTIME)


def endpoint(identity):
    return (f'https://api.github.com/repos/{REPO}/actions/runs/{identity["run_id"]}'
            f'/attempts/{identity["attempt"]}/jobs?per_page=100&page=1')


def selected_job(data, identity):
    value = parse_json(data)
    require(type(value.get('total_count')) is int and value['total_count'] == 1
            and type(value.get('jobs')) is list and len(value['jobs']) == 1,
            'this workflow requires exactly one job in the complete attempt')
    job = value['jobs'][0]
    require(type(job) is dict and job.get('name') == JOB
            and job.get('run_id') == int(identity['run_id'])
            and job.get('head_sha') == identity['head_sha']
            and job.get('runner_name') == identity['runner_name']
            and job.get('status') == 'in_progress' and job.get('conclusion') is None
            and integer(job.get('id'), 1) and integer(job.get('runner_id'), 1),
            'public job does not uniquely match this running job')
    require(job.get('run_url') == f'https://api.github.com/repos/{REPO}/actions/runs/{identity["run_id"]}',
            'public job repository binding differs')
    started = job.get('started_at')
    require(type(started) is str and started.endswith('Z'), 'job started_at missing or not UTC')
    stamp = dt.datetime.fromisoformat(started[:-1] + '+00:00')
    require(stamp.utcoffset() == dt.timedelta(0), 'job started_at timezone differs')
    return job, stamp


def elapsed_anchor(started, date_header, request_start, request_end):
    require(integer(request_start) and integer(request_end) and request_start <= request_end
            and request_end - request_start <= REQUEST_SECONDS * NANO, 'request timing invalid')
    require(type(date_header) is str and len(date_header) <= 128, 'HTTP Date missing')
    server = email.utils.parsedate_to_datetime(date_header)
    require(server is not None and server.utcoffset() == dt.timedelta(0) and server >= started,
            'HTTP Date precedes job start or is not UTC')
    delta = server - started
    age = (delta.days * 86400 + delta.seconds) * NANO + delta.microseconds * 1000
    # Date is the server response timestamp, not an authenticated time oracle.
    # Include the entire allowed freshness lag, request duration and two seconds
    # of timestamp granularity. This remains an estimate under the GitHub/runner
    # clock assumptions, never an unconditional scheduling guarantee.
    return age + request_end - request_start + (DATE_FRESHNESS_SECONDS + 2) * NANO


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        fp.close()
        raise GateError('API redirect refused')


@contextlib.contextmanager
def request_deadline():
    def expired(*_):
        raise TimeoutError('job API deadline')
    previous = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, REQUEST_SECONDS)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def fetch(identity):
    token = os.environ.pop('EC_JOB_BUDGET_TOKEN', '')
    require(re.fullmatch(r'[A-Za-z0-9._~+/-]{1,4096}={0,2}', token) is not None,
            'recording step Actions token missing or invalid')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    request = urllib.request.Request(endpoint(identity), method='GET', headers={
        'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': API_VERSION,
        'User-Agent': '3FS-EC-job-budget', 'Cache-Control': 'no-cache', 'Pragma': 'no-cache',
        'Authorization': 'Bearer ' + token})
    del token
    for attempt in range(3):
        try:
            start = clock()
            with request_deadline(), opener.open(request, timeout=REQUEST_SECONDS) as response:
                require(response.status == 200 and response.geturl() == endpoint(identity), 'unexpected API response')
                require(response.headers.get('Age', '0') == '0', 'cached API response refused')
                date_header = response.headers.get('Date')
                data = response.read(MAX_BODY + 1)
                require(len(data) <= MAX_BODY, 'oversized API response')
            end = clock()
            job, started = selected_job(data, identity)
            age = elapsed_anchor(started, date_header, start, end)
            # Sanity guard only. The age calculation uses the API server clock.
            server = email.utils.parsedate_to_datetime(date_header)
            require(abs((dt.datetime.now(dt.timezone.utc) - server).total_seconds()) <= DATE_FRESHNESS_SECONDS,
                    'HTTP Date not plausibly fresh')
            return data, job, date_header, start, end, age
        except urllib.error.HTTPError as error:
            code = error.code
            failure = {'kind': 'http', 'status_code': code if type(code) is int and 100 <= code <= 599 else None}
            error.close()
        except TimeoutError:
            failure = {'kind': 'timeout'}
        except urllib.error.URLError:
            failure = {'kind': 'transport'}
        # Only a closed set of categories and a bounded integer are published.
        # Never stringify exceptions, response bodies, headers or request objects.
        print(json.dumps({'status': 'job-api-request-failed', 'attempt': attempt + 1,
                          'failure': failure}, sort_keys=True))
        if attempt == 2:
            raise GateError('GitHub API unavailable after bounded retries') from None
        time.sleep(1)
    raise GateError('API request did not complete')


def write_new(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def read_private(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= limit,
                'private receipt owner, type, mode or size differs')
        data = stream.read(limit + 1)
        require(len(data) <= limit, 'oversized private receipt')
        return data


def record(parent, identity):
    require(not os.path.lexists(parent / RECORD_NAME) and not os.path.lexists(parent / BODY_NAME),
            'new budget receipt paths required')
    data, job, date_header, start, end, age = fetch(identity)
    value = {'schema': 1, 'identity': identity, 'api_version': API_VERSION, 'endpoint': endpoint(identity),
             'job_id': job['id'], 'runner_id': job['runner_id'], 'started_at': job['started_at'],
             'http_date': date_header, 'query_start_boottime_ns': start, 'query_end_boottime_ns': end,
             'elapsed_upper_at_query_end_ns': age, 'raw_sha256': digest(data),
             'driver_sha256': digest(Path(__file__).read_bytes()), 'clock': 'CLOCK_BOOTTIME',
             'date_freshness_seconds': DATE_FRESHNESS_SECONDS,
             'job_minutes': JOB_MINUTES, 'required_minutes': REQUIRED_MINUTES, 'lab_step_minutes': LAB_STEP_MINUTES}
    write_new(parent / BODY_NAME, data)
    encoded = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    write_new(parent / RECORD_NAME, encoded)
    print(json.dumps({'status': 'recorded', 'job_id': job['id'], 'run_id': identity['run_id'],
                      'attempt': identity['attempt'], 'started_at': job['started_at'],
                      'receipt_sha256': digest(encoded), 'clock': 'CLOCK_BOOTTIME'}, sort_keys=True))
    return 0


def remaining(value, data, identity, now):
    require(type(value.get('schema')) is int and value['schema'] == 1 and value.get('identity') == identity
            and value.get('api_version') == API_VERSION and value.get('endpoint') == endpoint(identity)
            and value.get('clock') == 'CLOCK_BOOTTIME'
            and value.get('date_freshness_seconds') == DATE_FRESHNESS_SECONDS
            and value.get('job_minutes') == JOB_MINUTES and value.get('required_minutes') == REQUIRED_MINUTES
            and value.get('lab_step_minutes') == LAB_STEP_MINUTES, 'budget receipt context or constants differ')
    require(value.get('raw_sha256') == digest(data), 'raw API evidence hash differs')
    job, started = selected_job(data, identity)
    require(value.get('job_id') == job['id'] and value.get('runner_id') == job['runner_id']
            and value.get('started_at') == job['started_at'], 'recorded API job fields differ')
    end = value['query_end_boottime_ns']
    age = elapsed_anchor(started, value['http_date'], value['query_start_boottime_ns'], end)
    require(value.get('elapsed_upper_at_query_end_ns') == age and integer(now) and now >= end,
            'budget anchor or monotonic continuation differs')
    return JOB_MINUTES * 60 * NANO - age - (now - end)


def check(parent, identity):
    encoded = read_private(parent / RECORD_NAME, 64 << 10)
    value = parse_json(encoded)
    require(value.get('driver_sha256') == digest(Path(__file__).read_bytes()), 'budget driver changed')
    data = read_private(parent / BODY_NAME, MAX_BODY)
    left = remaining(value, data, identity, clock())
    admitted = left >= REQUIRED_MINUTES * 60 * NANO
    print(json.dumps({'status': 'admitted' if admitted else 'insufficient-budget',
                      'job_id': value['job_id'], 'run_id': identity['run_id'], 'attempt': identity['attempt'],
                      'remaining_seconds_conservative_estimate': left // NANO,
                      'required_seconds': REQUIRED_MINUTES * 60, 'lab_step_minutes': LAB_STEP_MINUTES,
                      'receipt_sha256': digest(encoded), 'scope': 'admission_only_job_cap_authoritative',
                      'clock_assumption': 'GitHub_Date_and_started_at_timebase_and_runner_UTC_freshness'}, sort_keys=True))
    return 0 if admitted else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('record', 'check'))
    args = parser.parse_args()
    parent, identity = context()
    return record(parent, identity) if args.command == 'record' else check(parent, identity)


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:
        # No URL response body, headers, environment dump or arbitrary exception text.
        print(json.dumps({'status': 'budget-gate-failed', 'error_type': type(error).__name__,
                          'detail': str(error) if isinstance(error, GateError) else None}, sort_keys=True))
        sys.exit(1)

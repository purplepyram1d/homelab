"""Independent arrival watchdog; no endpoint commands, responses, network or credentials."""
import argparse
import contextlib
import datetime as dt
import json
import os
from pathlib import Path
import sqlite3
import stat
import time
import uuid

HOSTS = {'001': 'DC01', '003': 'SRV01'}
STALE_SECONDS = 900
FUTURE_SECONDS = 60
MAX_BYTES = 8 * 1024 * 1024
MAX_LINE = 256 * 1024
LOCATION = r'C:\ProgramData\HomelabHealth\sysmon-health.jsonl'


def utc(epoch):
    return dt.datetime.fromtimestamp(epoch, dt.timezone.utc).isoformat().replace('+00:00', 'Z')


def epoch(value):
    parsed = dt.datetime.fromisoformat(str(value).replace('Z', '+00:00'))
    if parsed.tzinfo is None:
        raise ValueError('timestamp requires timezone')
    return parsed.timestamp()


def candidate(event, now):
    """Only known authenticated-agent envelope + expected health file/rule/host."""
    agent = event.get('agent', {})
    rule = str(event.get('rule', {}).get('id'))
    agent_id = str(agent.get('id', ''))
    if rule not in ('100892', '100893') or agent_id not in HOSTS:
        return None
    health = event.get('data', {}).get('homelab_health', {})
    host = HOSTS[agent_id]
    location = str(event.get('location', '')).replace('\\\\', '\\').casefold()
    expected_status = 'ok' if rule == '100892' else 'fail'
    if (agent.get('name', '').casefold() != host.casefold()
            or health.get('host', '').casefold() != host.casefold()
            or health.get('kind') != 'sysmon'
            or health.get('status') != expected_status
            or location != LOCATION.casefold()
            or event.get('manager', {}).get('name') != 'siem01'):
        raise ValueError('health identity/envelope mismatch')
    sample, receipt = epoch(health['utc']), epoch(event['timestamp'])
    if sample > now + FUTURE_SECONDS or receipt > now + FUTURE_SECONDS or sample > receipt + FUTURE_SECONDS:
        raise ValueError('future or inconsistent clock')
    if sample <= 0 or receipt <= 0 or not str(event.get('id', '')):
        raise ValueError('missing native identity/time')
    return dict(host=host, sample=sample, receipt=receipt, source=str(event['id']), status=expected_status)


def read_tail(source, now):
    """One bounded current-file snapshot. Incomplete prefix/suffix never interpreted."""
    descriptor = os.open(source, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    with os.fdopen(descriptor, 'rb') as stream:
        file_stat = os.fstat(stream.fileno())
        if not stat.S_ISREG(file_stat.st_mode):
            raise ValueError('source is not regular')
        size = file_stat.st_size
        start = max(0, size - MAX_BYTES)
        stream.seek(start)
        data = stream.read(size - start)
    if start:
        data = data.split(b'\n', 1)[-1] if b'\n' in data else b''
    lines = data.split(b'\n')[:-1]
    newest, rejected, malformed = {}, 0, 0
    for line in lines:
        if not line:
            continue
        if len(line) > MAX_LINE:
            malformed += 1
            continue
        try:
            event = json.loads(line)
            if not isinstance(event, dict):
                raise ValueError('non-object source')
        except (ValueError, UnicodeError):
            malformed += 1
            continue
        try:
            item = candidate(event, now)
        except (ValueError, KeyError, TypeError, AttributeError):
            rejected += 1
            continue
        if item and (item['host'] not in newest or item['sample'] > newest[item['host']]['sample']):
            newest[item['host']] = item
    if malformed or rejected:
        # A source problem is visible independently; it cannot silently become a clean pass.
        error = 'invalid_bounded_source_records'
    else:
        error = None
    return newest, dict(bytes_read=len(data), tail_limited=bool(start), malformed=malformed,
                        rejected_health=rejected, error=error)


def connect(path):
    db = sqlite3.connect(path)
    db.execute('PRAGMA synchronous=FULL')
    db.executescript('''
      CREATE TABLE IF NOT EXISTS hosts(host TEXT PRIMARY KEY, first_seen REAL NOT NULL,
        sample REAL, receipt REAL, source TEXT, sample_status TEXT, mode TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS outbox(id TEXT PRIMARY KEY, created REAL NOT NULL,
        body TEXT NOT NULL, delivered REAL);
    ''')
    db.commit()
    return db


def queue(db, now, status, host='SIEM01', **details):
    event_id = str(uuid.uuid4())
    body = {'homelab_watch': dict(kind='sysmon_arrival', observer='siem01', status=status,
                target_host=host, utc=utc(now), threshold_seconds=STALE_SECONDS,
                monitor_event_id=event_id, **details)}
    db.execute('INSERT INTO outbox VALUES(?,?,?,NULL)',
               (event_id, now, json.dumps(body, separators=(',', ':'), sort_keys=True)))


def evaluate(db, now, observations, source_error=None):
    """Presence/freshness only: a fail report still proves its producer is reporting."""
    with db:
        prior = db.execute("SELECT value FROM metadata WHERE key='last_run'").fetchone()
        clock_bad = bool(prior and float(prior[0]) > now + FUTURE_SECONDS)
        if clock_bad:
            source_error = 'observer_clock_moved_backwards'
        previous_error = db.execute("SELECT value FROM metadata WHERE key='source_error'").fetchone()
        if source_error and (not previous_error or not previous_error[0]):
            queue(db, now, 'observer_error', reason=source_error)
        elif not source_error and previous_error and previous_error[0]:
            queue(db, now, 'observer_recovered', reason='source readable and clock consistent')
        db.execute('INSERT OR REPLACE INTO metadata VALUES(?,?)', ('source_error', source_error or ''))
        db.execute('INSERT OR REPLACE INTO metadata VALUES(?,?)', ('last_run', str(max(now, float(prior[0]) if prior else now))))
        result = {}
        for host in HOSTS.values():
            db.execute('INSERT OR IGNORE INTO hosts VALUES(?,?,NULL,NULL,NULL,NULL,?)', (host, now, 'starting'))
            row = db.execute('SELECT first_seen,sample,receipt,source,sample_status,mode FROM hosts WHERE host=?', (host,)).fetchone()
            first, sample, receipt, source, sample_status, old_mode = row
            item = observations.get(host)
            if item and not clock_bad and (sample is None or item['sample'] > sample):
                sample, receipt, source, sample_status = item['sample'], item['receipt'], item['source'], item['status']
            age = now - (sample if sample is not None else first)
            mode = 'stale' if age > STALE_SECONDS else ('fresh' if sample is not None else 'starting')
            if clock_bad:
                mode = old_mode
            if mode == 'stale' and old_mode != 'stale':
                queue(db, now, 'stale', host, age_seconds=round(age, 1),
                      last_sample_utc=utc(sample) if sample is not None else 'never_seen',
                      last_source_id=source or 'none', reason='No recent validated health report; cause not established')
            elif mode == 'fresh' and old_mode == 'stale':
                queue(db, now, 'recovered', host, last_sample_utc=utc(sample),
                      last_source_id=source, sample_status=sample_status,
                      reason='Validated health reports resumed; inspect reported service status separately')
            db.execute('UPDATE hosts SET sample=?,receipt=?,source=?,sample_status=?,mode=? WHERE host=?',
                       (sample, receipt, source, sample_status, mode, host))
            result[host] = dict(arrival=mode, age_seconds=round(age, 1), sample_status=sample_status,
                                last_sample_utc=utc(sample) if sample is not None else None,
                                last_source_id=source)
        db.execute('DELETE FROM outbox WHERE delivered IS NOT NULL AND created<?', (now - 7 * 86400,))
    return result


def drain(db, output, now):
    """Durable outbox, at least once. A crash after append can replay the same event ID."""
    count = 0
    for event_id, body in db.execute('SELECT id,body FROM outbox WHERE delivered IS NULL ORDER BY created,id').fetchall():
        if output.exists() and output.stat().st_size > 1024 * 1024:
            output.replace(output.with_suffix('.jsonl.1'))
        descriptor = os.open(output, os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0), 0o640)
        if hasattr(os, 'fchmod'):
            os.fchmod(descriptor, 0o640)
        with os.fdopen(descriptor, 'a', encoding='utf-8') as stream:
            stream.write(body + '\n')
            stream.flush()
            os.fsync(stream.fileno())
        with db:
            db.execute('UPDATE outbox SET delivered=? WHERE id=?', (now, event_id))
        count += 1
    return count


def run(source, state, output, now=None):
    now = time.time() if now is None else now
    try:
        observations, scan = read_tail(source, now)
    except (OSError, ValueError) as exc:
        observations, scan = {}, dict(error='source_' + type(exc).__name__, bytes_read=0)
    with contextlib.closing(connect(state)) as db:
        hosts = evaluate(db, now, observations, scan.get('error'))
        observer_error = db.execute("SELECT value FROM metadata WHERE key='source_error'").fetchone()[0]
        emitted = drain(db, output, now)
    return dict(utc=utc(now), hosts=hosts, scan=scan, emitted=emitted,
                observer_error=observer_error or None,
                result='REVIEW' if observer_error or any(h['arrival']=='stale' for h in hosts.values()) else 'PASS')


def main():
    import fcntl
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', default='/var/ossec/logs/alerts/alerts.json')
    parser.add_argument('--state', default='/var/lib/homelab-telemetry-watch/state.sqlite3')
    parser.add_argument('--output', default='/var/log/homelab-telemetry-watch/events.jsonl')
    args = parser.parse_args()
    with open(args.state + '.lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        result = run(Path(args.source), Path(args.state), Path(args.output))
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()

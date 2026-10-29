"""Deterministic, explainable detections operating only on local synthetic telemetry."""
from collections import defaultdict
from datetime import datetime, timedelta, timezone

def parse_time(value):
    result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    return result.replace(tzinfo=timezone.utc) if result.tzinfo is None else result.astimezone(timezone.utc)

def detect(events):
    """Returns findings tied to triggering event IDs; repeat runs are deterministic."""
    ordered = sorted(events, key=lambda e: (parse_time(e['timestamp']), e['id']))
    failed = defaultdict(list)
    probes = defaultdict(list)
    findings = []
    for event in ordered:
        event_type = event['event_type'].lower()
        action = event['action'].lower()
        ip = event.get('source_ip', '')
        time = parse_time(event['timestamp'])
        if event_type == 'authentication' and action == 'failure':
            failed[ip] = [t for t in failed[ip] if time - t < timedelta(minutes=10)]
            failed[ip].append(time)
            if len(failed[ip]) == 5:
                findings.append(dict(rule_id='AUTH_BRUTE_FORCE', event_id=event['id'], severity='high',
                                     title='5 failed logins from a single source within 10 minutes',
                                     technique='T1110', reason='Deterministic five-failure threshold'))
        if event_type == 'authentication' and action == 'success' and event.get('geo_label') == 'Unexpected Region':
            findings.append(dict(rule_id='GEO_ANOMALY', event_id=event['id'], severity='medium',
                                 title='Synthetic login location mismatch',technique='T1078',
                                 reason='Synthetic event explicitly labeled Unexpected Region; no real geolocation'))
        # SYNTHETIC HEURISTIC: distinct denied destination ports from one source.
        # This is a probe signal, not evidence of compromise.
        if event_type == 'firewall' and action in ('deny', 'denied', 'blocked'):
            destination = event.get('destination') or ''
            port = destination.rsplit(':', 1)[-1] if ':' in destination else ''
            if port.isdecimal() and 0 < int(port) < 65536:
                probes[ip] = [(t, p) for (t, p) in probes[ip] if time-t < timedelta(minutes=10)]
                probes[ip].append((time, int(port)))
                if len({p for _, p in probes[ip]}) == 5:
                    findings.append(dict(rule_id='PORT_SCAN_HEURISTIC',event_id=event['id'],
                                         severity='medium',title='5 distinct denied destination ports in 10 minutes',
                                         technique='T1046',reason='Synthetic multi-port probe heuristic; investigate context'))
        process = (event.get('process') or '').lower()
        if event_type == 'endpoint' and ('encodedcommand' in process or '-enc ' in process):
            findings.append(dict(rule_id='ENCODED_POWERSHELL',event_id=event['id'],severity='high',
                                 title='Encoded PowerShell command observed',technique='T1059.001',
                                 reason='Process command-line contains encoded execution indicator'))
    return findings

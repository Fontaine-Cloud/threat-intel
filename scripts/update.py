"""Refresh blocklist.txt and the daily statistics from Fontaine Cloud's public threat intelligence API."""

import datetime
import ipaddress
import json
import pathlib
import urllib.request

API = 'https://intel.fontaine.host/api'
ROOT = pathlib.Path(__file__).resolve().parent.parent
TOP = 25


def fetch(path):
    with urllib.request.urlopen(urllib.request.Request(f'{API}/{path}', headers={'User-Agent': 'Fontaine-Cloud/threat-intel'}), timeout=60) as response:
        return response.read().decode()


def blocklist(now):
    addresses = [line.strip() for line in fetch('blocklist.txt').splitlines() if line.strip() and not line.startswith('#')]
    if not addresses:
        raise SystemExit('The API returned an empty blocklist; keeping the current one')
    addresses = sorted({ipaddress.ip_address(address) for address in addresses}, key=lambda a: (a.version, a))
    header = ['# Fontaine Cloud threat intelligence: addresses seen attacking in the last 7 days, known research scanners left out',
              f'# Updated {now:%Y-%m-%d %H:%M} UTC, {len(addresses)} addresses',
              '# https://fontaine.host/threat-intelligence/ - CC BY 4.0']
    (ROOT / 'blocklist.txt').write_text('\n'.join(header + [str(a) for a in addresses]) + '\n')
    badge = {'schemaVersion': 1, 'label': 'addresses', 'message': f'{len(addresses):,}', 'color': '0758e8', 'labelColor': '111d31'}
    (ROOT / 'badge.json').write_text(json.dumps(badge) + '\n')


def stats(now):
    day = now.date() - datetime.timedelta(days=1)
    path = ROOT / 'stats' / f'{day:%Y}' / f'{day}.json'
    if path.exists():
        return
    summary = json.loads(fetch('summary'))
    window = summary['day']
    pick = lambda rows, *keys: [{key: row[key] for key in keys} for row in rows[:TOP]]
    snapshot = {
        'window_end': datetime.datetime.fromtimestamp(summary['generated_at'], datetime.UTC).strftime('%Y-%m-%dT%H:%M:%SZ'),
        'totals': window['totals'],
        'attack_types': pick(window['threats'], 'id', 'name', 'category', 'cve', 'attacks', 'sources'),
        'ports': pick(window['ports'], 'port', 'attacks', 'sources'),
        'countries': pick(window['countries'], 'country', 'attacks', 'sources'),
        'networks': pick(window['networks'], 'asn', 'name', 'country', 'attacks', 'sources'),
        'tools': pick(window['tools'], 'tool', 'user_agent', 'attacks', 'sources'),
        'logins': pick(window['credentials'], 'username', 'password', 'attempts', 'sources'),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(snapshot, indent=1) + '\n')


if __name__ == '__main__':
    now = datetime.datetime.now(datetime.UTC)
    blocklist(now)
    stats(now)

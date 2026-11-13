#!/usr/bin/env python3
"""Prepare only the two locked ISA-L packages in a fresh private CI prefix.

This is the package preparation used by the passed codec runner, separated for
the full build. It neither installs packages nor starts services or compilers.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import urllib.request


PROVIDER_SHA = '40ccd5e5abaff0451feff750d2b011370a546ac4706d1b06b9285ac26eda2c3c'
PROVIDER_RELATIVE = 'usr/lib/x86_64-linux-gnu/libisal.so.2.0.31'
PACKAGES = {
    'libisal-dev': ('293bf52a13045fd95b202fe83cdc56927923f893d8f7e7d9aa8ca2884e2f3f67', 27434),
    'libisal2': ('94ae550dc0d4cbd8405a9626034dcfac655edad97b5d70d38cf4c42388111e14', 117168),
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(65536), b''):
            value.update(block)
    return value.hexdigest()


def packages_from_lock(path):
    lock = json.loads(path.read_text(encoding='utf-8'))
    packages = [p for p in lock['packages'] if p['package'] in PACKAGES]
    require(len(packages) == 2 and {p['package'] for p in packages} == set(PACKAGES),
            'Expected exactly the two locked ISA-L packages')
    for item in packages:
        name = item['package']
        expected_sha, expected_size = PACKAGES[name]
        expected_url = ('https://archive.ubuntu.com/ubuntu/pool/universe/libi/libisal/'
                        + name + '_2.31.0-0.1build1_amd64.deb')
        require(item['version'] == '2.31.0-0.1build1' and item['architecture'] == 'amd64'
                and item['url'] == expected_url and item['sha256'] == expected_sha
                and type(item['size']) is int and item['size'] == expected_size,
                'ISA-L source lock differs from the validated packages')
    return packages


def fetch(item, archive):
    request = urllib.request.Request(item['url'], headers={'User-Agent': 'ec-native-fixed-input/1'})
    with urllib.request.urlopen(request, timeout=60) as response, archive.open('xb') as out:
        require(response.status == 200 and response.url == item['url'], 'Unexpected ISA-L download redirect/status')
        length = 0
        while True:
            block = response.read(65536)
            if not block:
                break
            length += len(block)
            require(length <= item['size'], 'Locked ISA-L download is oversized')
            out.write(block)
    require(length == item['size'] and digest(archive) == item['sha256'], 'ISA-L download mismatch')


def provider_record(prefix):
    prefix = prefix.resolve(strict=True)
    provider = (prefix / 'usr/lib/x86_64-linux-gnu/libisal.so').resolve(strict=True)
    require(provider.is_relative_to(prefix) and provider == prefix / PROVIDER_RELATIVE
            and provider.is_file(), 'ISA-L provider escaped or differs from the locked library')
    require(digest(provider) == PROVIDER_SHA, 'ISA-L provider SHA differs from the validated library')
    return {'path': str(provider), 'sha256': PROVIDER_SHA}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--work', required=True, type=Path)
    args = parser.parse_args()
    require(platform.system() == 'Linux' and platform.machine() == 'x86_64' and os.getuid() != 0,
            'Use the ordinary Linux x86_64 build user')
    os.umask(0o077)
    source, work = args.source.resolve(strict=True), args.work.resolve(strict=True)
    require(source.is_dir() and work.is_dir() and not work.is_relative_to(source), 'Invalid build/source roots')
    require(work.stat().st_uid == os.getuid() and not work.stat().st_mode & 0o077,
            'Build work must be owned and private')
    lock = source / 'scripts/ec/reference/downloads.json'
    before = digest(lock)
    packages = packages_from_lock(lock)
    prefix, archives = work / 'isal-prefix', work / 'isal-downloads'
    prefix.mkdir(mode=0o700)  # Exclusive: failed preparations are never adopted.
    archives.mkdir(mode=0o700)
    provenance = work / 'provenance'
    require(provenance.is_dir() and not provenance.is_symlink(), 'Missing private build provenance')
    commands = []
    for item in packages:
        archive = archives / (item['package'] + '.deb')
        fetch(item, archive)
        for operation, argv in (
            ('metadata', ['/usr/bin/dpkg-deb', '-f', str(archive), 'Package', 'Version', 'Architecture']),
            ('extract', ['/usr/bin/dpkg-deb', '-x', str(archive), str(prefix)]),
        ):
            label = 'isal-' + operation + '-' + item['package']
            stdout, stderr = provenance / (label + '.stdout'), provenance / (label + '.stderr')
            with stdout.open('xb') as out, stderr.open('xb') as err:
                result = subprocess.run(argv, stdout=out, stderr=err, check=False)
            row = {'phase': label, 'argv': argv, 'exit_code': result.returncode,
                   'stdout_sha256': digest(stdout), 'stderr_sha256': digest(stderr)}
            commands.append(row)
            print(json.dumps(row), flush=True)
            require(result.returncode == 0, 'ISA-L package command failed: ' + label)
            if operation == 'metadata':
                actual = dict(line.split(': ', 1) for line in stdout.read_text().splitlines())
                require(actual == {'Package': item['package'], 'Version': item['version'],
                                   'Architecture': item['architecture']}, 'ISA-L package metadata mismatch')
    provider = provider_record(prefix)
    require(digest(lock) == before, 'ISA-L source lock changed')
    record = {'schema': 1, 'status': 'private-packages-prepared-not-executed', 'backend': 'isal',
              'source_lock_sha256': before, 'helper_sha256': digest(Path(__file__).resolve()),
              'prefix': str(prefix), 'provider': provider, 'packages': packages, 'commands': commands,
              'system_install_performed': False, 'package_hooks_executed': False}
    path = provenance / 'isal-prepare.json'
    with path.open('x', encoding='utf-8') as stream:
        json.dump(record, stream, indent=2)
        stream.write('\n')
    print(json.dumps({'isal_prepare': record, 'receipt_sha256': digest(path)}), flush=True)


if __name__ == '__main__':
    main()

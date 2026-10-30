#!/usr/bin/env bash
set -euo pipefail
BUNDLE="${1:?Usage: fetch-fdb.sh BUNDLE_DIRECTORY}"
[[ "$BUNDLE" == /* && "$BUNDLE" != / ]] || { echo "Use an absolute task directory" >&2; exit 1; }
mkdir -p "$BUNDLE"/{downloads,bin,lib,fdb-package}
BUNDLE="$(realpath "$BUNDLE")"
exec 9>"$BUNDLE/fdb-download.lock"
flock -n 9 || { echo "FDB preparation already running" >&2; exit 1; }
cd "$BUNDLE/downloads"
BASE=https://github.com/apple/foundationdb/releases/download/7.3.63
for role in clients server; do
  package="foundationdb-${role}_7.3.63-1_amd64.deb"
  curl --fail --location --retry 3 --connect-timeout 20 --output "$package.sha256" "$BASE/$package.sha256"
  if [[ ! -f "$package" ]]; then
    curl --fail --location --retry 3 --connect-timeout 20 --continue-at - --output "$package.part" "$BASE/$package"
    expected="$(awk '{print $1}' "$package.sha256")"
    [[ "$expected" =~ ^[a-fA-F0-9]{64}$ ]] || { echo "Invalid official checksum" >&2; exit 1; }
    printf '%s  %s\n' "$expected" "$package.part" | sha256sum --check -
    mv -- "$package.part" "$package"
  fi
  sha256sum --check "$package.sha256"
  dpkg-deb --extract "$package" "$BUNDLE/fdb-package"
done
install -m 755 "$BUNDLE/fdb-package/usr/sbin/fdbserver" "$BUNDLE/bin/fdbserver"
install -m 755 "$BUNDLE/fdb-package/usr/bin/fdbcli" "$BUNDLE/bin/fdbcli"
install -m 755 "$BUNDLE/fdb-package/usr/lib/libfdb_c.so" "$BUNDLE/lib/libfdb_c.so"
"$BUNDLE/bin/fdbserver" --version
"$BUNDLE/bin/fdbcli" --version
sha256sum "$BUNDLE/bin/fdbserver" "$BUNDLE/bin/fdbcli" "$BUNDLE/lib/libfdb_c.so" > "$BUNDLE/fdb-binaries.sha256"
echo "FDB packages extracted only; no package hooks, services or database started."

#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PKG="vaultlog"
if [[ ! -x "$ROOT/.venv/bin/python" ]]; then
  echo "Missing .venv. Run: python3 -m venv .venv && .venv/bin/pip install -e ." >&2
  exit 1
fi

VERSION="$("$ROOT/.venv/bin/python" - <<'PY'
from pathlib import Path
import tomllib

print(tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))["project"]["version"])
PY
)"
ARCH="${DEB_ARCH:-$(dpkg --print-architecture)}"
BUILD_ROOT="$ROOT/build/deb/${PKG}"
INSTALL_ROOT="$BUILD_ROOT/opt/vaultlog"
OUT_DIR="$ROOT/dist"
DEB_PATH="$OUT_DIR/${PKG}_${VERSION}_${ARCH}.deb"

rm -rf "$BUILD_ROOT"
mkdir -p "$INSTALL_ROOT/app" "$BUILD_ROOT/usr/bin" "$BUILD_ROOT/usr/share/doc/$PKG" "$BUILD_ROOT/DEBIAN" "$OUT_DIR"

cp -a "$ROOT/vaultlog" "$INSTALL_ROOT/app/"
cp -a "$ROOT/.venv" "$INSTALL_ROOT/venv"
cp "$ROOT/README.md" "$BUILD_ROOT/usr/share/doc/$PKG/README.md"

SITE_PACKAGES="$("$INSTALL_ROOT/venv/bin/python" - <<'PY'
import site

print(site.getsitepackages()[0])
PY
)"
find "$SITE_PACKAGES" -maxdepth 1 \( -name '__editable__*' -o -name 'vaultlog-*.dist-info' -o -name 'vaultlog.egg-info' \) -exec rm -rf {} +
find "$BUILD_ROOT" -type d -name '__pycache__' -prune -exec rm -rf {} +
find "$BUILD_ROOT" -type f -name '*.pyc' -delete

cat > "$BUILD_ROOT/usr/bin/vaultlog" <<'SH'
#!/bin/sh
export PYTHONPATH="/opt/vaultlog/app"
exec /opt/vaultlog/venv/bin/python -P -m vaultlog.cli "$@"
SH
chmod 0755 "$BUILD_ROOT/usr/bin/vaultlog"

INSTALLED_SIZE="$(du -sk "$BUILD_ROOT" | awk '{print $1}')"
cat > "$BUILD_ROOT/DEBIAN/control" <<CONTROL
Package: $PKG
Version: $VERSION
Section: utils
Priority: optional
Architecture: $ARCH
Depends: python3 (>= 3.11)
Installed-Size: $INSTALLED_SIZE
Maintainer: vaultlog <vaultlog@localhost>
Description: Encrypted terminal journal with CLI, TUI, and Git backup
 Vaultlog stores journal entries as encrypted files and provides
 commands for verification, autosave configuration, and Git backups.
CONTROL

find "$BUILD_ROOT" -type d -exec chmod 0755 {} +
find "$BUILD_ROOT/opt/vaultlog" -type f -exec chmod 0644 {} +
chmod 0755 "$BUILD_ROOT/usr/bin/vaultlog"
find "$BUILD_ROOT/opt/vaultlog/venv/bin" -type f -exec chmod 0755 {} +

dpkg-deb --build --root-owner-group "$BUILD_ROOT" "$DEB_PATH"
echo "$DEB_PATH"

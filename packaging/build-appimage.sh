#!/usr/bin/env bash
# Build dist/LanScanMan-x86_64.AppImage: a self-contained app with its own
# Python (manylinux, so it runs on most distros) and all Python libraries.
# nmap, rsync, ssh and a terminal still come from the host system.
#
#   ./packaging/build-appimage.sh            (uses ./.venv)
#   PY=python3 ./packaging/build-appimage.sh (any Python with `build` and
#                                             `python-appimage` installed; used by CI)
set -euo pipefail
cd "$(dirname "$0")/.."
PY=${PY:-.venv/bin/python}
# Absolute path WITHOUT resolving symlinks (resolving a venv's python would
# escape the venv); a bare name like "python" is looked up on PATH.
case "$PY" in
    */*) PY="$(cd "$(dirname "$PY")" && pwd)/$(basename "$PY")" ;;
    *)   PY="$(command -v "$PY")" ;;
esac
PYVER=${PYVER:-3.12}

# Never leave an old AppImage around to be tested or published by mistake
rm -rf build/appimage dist/*.whl dist/LanScanMan-x86_64.AppImage
"$PY" -m build --wheel --outdir dist >/dev/null
WHEEL=$(ls "$PWD"/dist/lanscanman-*.whl)

# Recipe = static files + a requirements.txt pointing at the fresh wheel
mkdir -p build/appimage
cp -r packaging/appimage/lanscanman build/appimage/
echo "$WHEEL" > build/appimage/lanscanman/requirements.txt

(cd build/appimage && "$PY" -m python_appimage build app -p "$PYVER" lanscanman)
mv build/appimage/*.AppImage dist/LanScanMan-x86_64.AppImage
echo "Built dist/LanScanMan-x86_64.AppImage"

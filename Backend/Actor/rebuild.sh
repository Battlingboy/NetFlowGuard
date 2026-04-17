#!/bin/bash

set -e

echo "====== [1/3] Cleaning old build directory... ======"
rm -rf build

echo "====== [2/3] Configuring build with Meson... ======"
meson setup build

echo "====== [3/3] Compiling with Ninja... ======"
ninja -C build

echo "====== Build Success! ======"
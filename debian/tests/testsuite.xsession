#!/bin/sh
export LANG=C.UTF-8
export LC_ALL=C.UTF-8

mkdir -p debian/tests.home || true
trap 'rm -rf debian/tests.home' EXIT

export HOME="$(pwd)/debian/tests.home"
export XDG_CACHE_HOME="$(pwd)/debian/tests.home"

openbox &
sleep 5
kbuildsycoca5
dh_auto_test --no-parallel

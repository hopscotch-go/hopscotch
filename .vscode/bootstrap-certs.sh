#!/bin/sh
# Fast path for launch.json: skip compiling if certs already exist.
# Serializes the first run so the foo/bar/baz compound does not fire
# three `go run` processes at once.
set -e
cd "$(dirname "$0")/.."

dir=examples/.local

certs_ok() {
	[ -f "$dir/ca.crt" ] && [ -f "$dir/foo.crt" ] && [ -f "$dir/bar.crt" ] && [ -f "$dir/baz.crt" ] && [ -f "$dir/hosts" ]
}

if certs_ok; then
	exit 0
fi

mkdir -p "$dir"
lock=$dir/.task.lock
while ! mkdir "$lock" 2>/dev/null; do
	if certs_ok; then
		exit 0
	fi
	sleep 0.05
done
trap 'rmdir "$lock"' EXIT

if certs_ok; then
	exit 0
fi

# examples/.local is gitignored throwaway material. A leftover ca.key
# without ca.crt (or the reverse) is usually from deleting certs after a
# SAN-scheme change; `ca bootstrap` refuses to invent the missing half.
if [ -f "$dir/ca.key" ] && [ ! -f "$dir/ca.crt" ]; then
	rm -f "$dir/ca.key"
fi
if [ -f "$dir/ca.crt" ] && [ ! -f "$dir/ca.key" ]; then
	rm -f "$dir/ca.crt"
fi

go run . ca bootstrap --dir "$dir" --node foo --node bar --node baz

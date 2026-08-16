#!/bin/sh
# Certs for the multi-process cycle mesh (launch.json compound).
set -e
cd "$(dirname "$0")/.."

dir=examples/.local/cycle
nodes="foo bar baz buzz bizz mid1 mid2 mid3 blaz"

certs_ok() {
	[ -f "$dir/ca.crt" ] || return 1
	[ -f "$dir/hosts" ] || return 1
	for n in $nodes; do
		[ -f "$dir/$n.crt" ] || return 1
	done
	return 0
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

if [ -f "$dir/ca.key" ] && [ ! -f "$dir/ca.crt" ]; then
	rm -f "$dir/ca.key"
fi
if [ -f "$dir/ca.crt" ] && [ ! -f "$dir/ca.key" ]; then
	rm -f "$dir/ca.crt"
fi

# shellcheck disable=SC2086
go run . ca bootstrap --dir "$dir" $(for n in $nodes; do printf -- '--node %s ' "$n"; done)

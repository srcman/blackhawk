#!/usr/local/bin/bash

# Creates an image of the current publication hierarchy.
# Needs Graphviz. Doesn't take any arguments.
#
# Note that the order of sub-objects, e.g. pages under a version, is
# NOT preserved.

die() {
	echo "Error: $@"
	exit 1
}


[ `which dot` ]              || die "Is graphics/graphviz really installed?"
[ `which psirptest` ]        || die "Is psirptest installed?"
[ -e ./parse_pitstatus.awk ] || die "Are you in the right directory?"
[ -e ./remove_scope_versions.awk ] || die "Do you have all the required files?"
[ -e ./atoidtoa.py ]               || die "Do you have all the required files?"

psirptest -i | ./parse_pitstatus.awk | sort | ./remove_scope_versions.awk > /tmp/status.dot.$$
dot -Tpng /tmp/status.dot.$$ -o status.png >/dev/null 2>&1
#dot -Teps /tmp/status.dot.$$ -o status.eps >/dev/null 2>&1
rm /tmp/status.dot.$$

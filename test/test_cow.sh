#!/bin/sh

# Test publishing data and then subscribing to it. Modifications to
# the original publication should not appear in the subscribed data
# (and vice versa, if writing to subscribed data is allowed).

pubandsub -r 1000000000000000000000000000000000000000000000000000000000000003
pubandsub -r 1000000000000000000000000000000000000000000000000000000000000003 -c
pubandsub -r 1000000000000000000000000000000000000000000000000000000000000003 -d

#!/bin/sh

find . -name '*.[hc]' |xargs etags --append

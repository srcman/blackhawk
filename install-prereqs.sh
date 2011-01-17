pkg_add -r autotools
pkg_add -r python26 || pkg_add ftp://ftp.freebsd.org/pub/FreeBSD/ports/amd64/packages/Latest/python26.tbz
pkg_add -r swig
pkg_add -r ruby

test -d /pubsub || mkdir /pubsub

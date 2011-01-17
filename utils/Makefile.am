#
# Copyright (C) 2009-2010, Oy L M Ericsson Ab, NomadicLab.
# All rights reserved.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License version
# 2 as published by the Free Software Foundation.
#
# Alternatively, this software may be distributed under the terms of
# the BSD license.
#
# See LICENSE and COPYING for more details.
#

#SUBDIRS = 

# XXX
install-exec-hook:
	cp -pf loadps $(sbindir)/
	cp -pf unloadps $(sbindir)/
	cp -pf reloadps $(sbindir)/
	cp -pf pubsub $(sysconfdir)/rc.d/

# XXX
uninstall-hook:
	test ! -f $(sbindir)/loadps || rm -f $(sbindir)/loadps
	test ! -f $(sbindir)/unloadps || rm -f $(sbindir)/unloadps
	test ! -f $(sbindir)/reloadps || rm -f $(sbindir)/reloadps
	test ! -f $(sysconfdir)/rc.d/pubsub || rm -f $(sysconfdir)/rc.d/pubsub

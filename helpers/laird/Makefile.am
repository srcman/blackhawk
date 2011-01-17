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

HELPERNAME=laird

pkgpyexec_PYTHON = $(HELPERNAME).py

# XXX
install-exec-hook:
	test -x $(pkgpyexecdir)/$(HELPERNAME).py \
	|| chmod u+x $(pkgpyexecdir)/$(HELPERNAME).py
	test -L $(sbindir)/$(HELPERNAME) \
	|| ln -s $(pkgpyexecdir)/$(HELPERNAME).py $(sbindir)/$(HELPERNAME)

# XXX
uninstall-hook:
	test ! -L $(sbindir)/$(HELPERNAME) \
	|| rm -f $(sbindir)/$(HELPERNAME)

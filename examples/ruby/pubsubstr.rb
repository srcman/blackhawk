#!/usr/bin/env ruby
#
# Copyright (C) 2009, Oy L M Ericsson Ab, NomadicLab <pubsub@nomadiclab.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.
#
# Alternatively, this software may be distributed under the terms of the BSD
# license.
#
# See LICENSE and COPYING for more details.
#

require 'libpsirp_rb'

str = ""
for i in ?\s..?~ do
# !"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~
  str += i.chr
end


sid = "\000" * Libpsirp_rb::PSIRP_ID_LEN # "Scope 0"
rid = Libpsirp_rb.psirp_rb_atoid("::aabb")

p "psirp_rb_publish_string(" + sid + "," + rid + "," + str + "...):"
y = Libpsirp_rb.psirp_rb_publish_string(sid, rid, str)
p y # psirp_pub_t object

p "psirp_subscribe(" + sid + "," + rid + "):"
z = Libpsirp_rb.psirp_rb_subscribe_sync(sid, rid, 500)
p z # return code and psirp_pub_t object
spub = z[1]

p "psirp_rb_pub_to_string(" + spub.to_s + "):"
sstr = Libpsirp_rb.psirp_rb_pub_to_string(spub)
p sstr

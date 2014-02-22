#!/usr/bin/perl
#
# Test suite for Authen::Kerberos::Kadmin basic functionality.
#
# Written by Russ Allbery <eagle@eyrie.org>
# Copyright 2014
#     The Board of Trustees of the Leland Stanford Junior University
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.

use 5.010;
use autodie;
use strict;
use warnings;

use File::Copy qw(copy);

use Test::More tests => 6;

BEGIN {
    use_ok('Authen::Kerberos::Kadmin');
}

# Make a temporary copy of the test database so that we don't create spurious
# changes in the source.
mkdir('t/tmp');
copy('t/data/kdb/heimdal.db', 't/tmp/heimdal.db')
  or die "$0: cannot create t/tmp/heimdal.db: $!\n";

# Clean up the temporary database copy on any exit.
END {
    unlink('t/tmp/heimdal.db');
    rmdir('t/tmp');
}

# Create the Authen::Kerberos::Kadmin object.
my $kadmin = Authen::Kerberos::Kadmin->new(
    {
        db_name => 'db:./t/tmp/heimdal',
        realm   => 'TEST.EXAMPLE.COM',
        server  => 1,
    }
);
isa_ok($kadmin, 'Authen::Kerberos::Kadmin');

# Test password change.  At the moment, we don't check whether the password
# change is performed in the database.  We'll do that later.
ok(eval { $kadmin->chpass('test@TEST.EXAMPLE.COM', 'some password') },
    'Password change is successful');
is($@, q{}, '...with no exception');

# The same should fail if we attempt it with an unknown database.
$kadmin = Authen::Kerberos::Kadmin->new(
    {
        db_name => 'db:./t/tmp/bogus',
        realm   => 'TEST.EXAMPLE.COM',
        server  => 1,
    }
);
ok(!eval { $kadmin->chpass('test@TEST.EXAMPLE.COM', 'some password') },
    'Password fails with bogus database');
like(
    $@,
    qr{ \A kadm5_chpass_principal: [ ] opening .* }xms,
    '...with correct error'
);

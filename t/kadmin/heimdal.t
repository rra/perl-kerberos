#!/usr/bin/perl
#
# Test suite for Authen::Kerberos::Kadmin basic functionality.
#
# Written by Russ Allbery <rra@cpan.org>
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

use Test::More tests => 20;

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

# Force use of our local kdc.conf.
local $ENV{KRB5_CONFIG} = 't/data/kdb/kdc.conf';

# Create the Authen::Kerberos::Kadmin object.
my $kadmin = Authen::Kerberos::Kadmin->new(
    {
        password_quality => 1,
        realm            => 'TEST.EXAMPLE.COM',
        server           => 1,
    }
);
isa_ok($kadmin, 'Authen::Kerberos::Kadmin');

# Get a list of principals.
my @principals = sort($kadmin->list(q{*}));
my @wanted     = qw(
  WELLKNOWN/ANONYMOUS@TEST.EXAMPLE.COM
  WELLKNOWN/org.h5l.fast-cookie@WELLKNOWN:ORG.H5L
  changepw/kerberos@TEST.EXAMPLE.COM
  default@TEST.EXAMPLE.COM
  kadmin/admin@TEST.EXAMPLE.COM
  kadmin/changepw@TEST.EXAMPLE.COM
  kadmin/hprop@TEST.EXAMPLE.COM
  krbtgt/TEST.EXAMPLE.COM@TEST.EXAMPLE.COM
  test@TEST.EXAMPLE.COM
);
is_deeply(\@principals, \@wanted, 'List of principals');
is(scalar($kadmin->list(q{*})),
    scalar(@wanted), '...and returns count in scalar context');

# Retrieve a known entry.
my $entry = $kadmin->get('test@TEST.EXAMPLE.COM');
isa_ok($entry, 'Authen::Kerberos::Kadmin::Entry');
is($entry->last_password_change, 1_393_043_331, 'Last password change time');
is($entry->password_expiration,  0,             'No password expiration');

# Test password change.  At the moment, we don't check whether the password
# change is performed in the database.  We'll do that later.
ok(eval { $kadmin->chpass('test@TEST.EXAMPLE.COM', 'some password') },
    'Password change is successful');
is($@, q{}, '...with no exception');

# Check that the last password change time was updated.
$entry = $kadmin->get('test@TEST.EXAMPLE.COM');
ok(time - $entry->last_password_change < 10, 'Last password change updated');

# Set the password expiration for this entry and confirm that it changed.
my $expires = time + 10;
is($entry->password_expiration($expires),
    $expires, 'Setting password expiration returns the correct value');
ok(eval { $kadmin->modify($entry) }, 'Modify password expiration');
is($@, q{}, '...with no exception');
$entry = $kadmin->get('test@TEST.EXAMPLE.COM');
is($entry->password_expiration, $expires, '...and expiration changed');

# Test password change to something that should be rejected by the password
# quality check.
ok(
    !eval { $kadmin->chpass('test@TEST.EXAMPLE.COM', 'password') },
    'Password change to bad-quality password rejected'
);
my $error = $@;
isa_ok($error, 'Authen::Kerberos::Exception', 'Thrown exception');
my ($function, $message);
if (ref($error) && $error->isa('Authen::Kerberos::Exception')) {
    $function = $error->function;
    $message  = $error->message;
}
is($function, 'kadm5_check_password_quality', '...with correct function');
is(
    $message,
    'External password quality program failed: weak password',
    '...and correct message'
);

# The same should fail if we attempt it with an unknown database.
$kadmin = Authen::Kerberos::Kadmin->new(
    {
        realm  => 'BOGUS.EXAMPLE.COM',
        server => 1,
    }
);
ok(!eval { $kadmin->chpass('test@TEST.EXAMPLE.COM', 'some password') },
    'Password fails with bogus database');
like(
    $@,
    qr{ \A kadm5_chpass_principal: [ ] opening .* }xms,
    '...with correct error'
);

#!/usr/bin/perl
#
# Test suite for Authen::Kerberos keytab methods.
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

use Test::More tests => 24;

BEGIN {
    use_ok('Authen::Kerberos');
    use_ok('Authen::Kerberos::Keytab');
}

# Information about the contents of t/keytabs/fake-keytab.  These will have to
# be changed if the test keytab is regenerated.
my $TEST_KVNO      = 3;
my $TEST_PRINCIPAL = 'service/fake-keytab@test-k5.stanford.edu';
my $TEST_TIMESTAMP = 1200690955;

# Force use of our local krb5.conf so that testing doesn't depend on the local
# system Kerberos configuration.
local $ENV{KRB5_CONFIG} = 't/data/krb5.conf';

# Open the keytab.
my $krb5 = Authen::Kerberos->new;
my $keytab = $krb5->keytab('FILE:t/data/keytabs/fake-keytab');
isa_ok($keytab, 'Authen::Kerberos::Keytab');

# Check obtaining a count of entries.
is(scalar($keytab->entries), 4, 'Entry count in keytab');

# Check the entries against the test data.
my @entries = $keytab->entries;
for my $i (0..$#entries) {
    my $entry = $entries[$i];
    isa_ok($entry, 'Authen::Kerberos::KeytabEntry', "Entry $i");
    my $principal = $entry->principal;
    isa_ok($principal, 'Authen::Kerberos::Principal', "Principal of entry $i");
    is("$principal",      $TEST_PRINCIPAL, "Principal of entry $i");
    is($entry->kvno,      $TEST_KVNO,      "KVNO of entry $i");
    is($entry->timestamp, $TEST_TIMESTAMP, "Timestamp of entry $i");
}

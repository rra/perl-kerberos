#!/usr/bin/perl
#
# Test suite for Authen::Kerberos initial authentication.
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

use Test::More;

# We can only run this test if we have a local keytab.
if (!-f 't/config/keytab') {
    plan skip_all => 'Authentication tests not configured';
}

# We can proceed.  Output the plan.
plan tests => 5;

# Load the relevant modules.
require_ok('Authen::Kerberos');
require_ok('Authen::Kerberos::Keytab');

# Open the keytab.
my $krb5   = Authen::Kerberos->new;
my $keytab = $krb5->keytab('FILE:t/config/keytab');

# Get the principal of the first entry.
my ($entry) = $keytab->entries;
my $principal = $entry->principal->to_string;

# Authenticate and request the krbtgt in the realm of the principal.
my ($realm) = ($principal =~ m{ \@ (.*) \z }xms);
my $args = {
    principal => $principal,
    keytab    => $keytab,
    service   => "krbtgt/$realm\@$realm",
};
my $creds = $krb5->authenticate($args);
isa_ok($creds, 'Authen::Kerberos::Creds', 'Return from authenticate');

# Check whether the credentials look correct.
is($creds->client->to_string, $principal,              'Creds client');
is($creds->server->to_string, "krbtgt/$realm\@$realm", 'Creds server');

#!/usr/bin/perl
#
# Test suite for Authen::Kerberos basic functionality.
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

use Test::More tests => 4;

BEGIN {
    use_ok('Authen::Kerberos');
}

# Force use of our local krb5.conf so that testing doesn't depend on the local
# system Kerberos configuration.
local $ENV{KRB5_CONFIG} = 't/data/krb5.conf';

# Test creation of a Kerberos context (Authen::Kerberos object).
my $krb5 = Authen::Kerberos->new;
isa_ok($krb5, 'Authen::Kerberos');

# Create a principal (Authen::Kerberos::Principal object).
my $principal = $krb5->principal('test@EXAMPLE.COM');
isa_ok($principal, 'Authen::Kerberos::Principal');
is("$principal", 'test@EXAMPLE.COM', 'Principal is correct');

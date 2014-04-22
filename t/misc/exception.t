#!/usr/bin/perl
#
# Test suite for Authen::Kerberos::Exception
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
use strict;
use warnings;

use Test::More tests => 12;

BEGIN {
    use_ok('Authen::Kerberos::Exception');
}

# We have to create an exception by hand, since there is (intentionally) no
# Perl interface to create one and currently we don't support any functions
# that let us easily generate a real exception.
my $exception = {
    code     => -1_765_328_383,
    message  => 'A Kerberos error message',
    function => 'krb5_foo',
    file     => 'exception.t',
    line     => 10,
};
bless($exception, 'Authen::Kerberos::Exception');

# Check the accessors.
is($exception->code,     -1_765_328_383,             'code');
is($exception->message,  'A Kerberos error message', 'message');
is($exception->function, 'krb5_foo',                 'function');

# Check the string representation.
is($exception->to_string,
    'krb5_foo: A Kerberos error message at exception.t line 10', 'to_string');
is("$exception", 'krb5_foo: A Kerberos error message at exception.t line 10',
    'stringify');

# The function, file, and line are optional.  Try without them.
delete $exception->{function};
delete $exception->{file};
delete $exception->{line};
is($exception->to_string, 'A Kerberos error message', 'to_string short');
is("$exception",          'A Kerberos error message', 'stringify short');

# Check cmp.
my $string = "$exception";
is($exception cmp $string, 0,  'cmp equal');
is($string cmp $exception, 0,  'cmp equal reversed');
is($exception cmp 'Test',  -1, 'cmp unequal');
is('Test' cmp $exception,  1,  'cmp unequal reversed');

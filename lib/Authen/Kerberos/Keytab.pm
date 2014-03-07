# Wrapper class for Kerberos keytab objects.
#
# This class provides the Perl representation of a krb5_keytab structure as
# used in the Kerberos API.  Most of the implementation is in the XS code
# underlying Authen::Kerberos.  This file provides documentation and some
# additional code that's easier to represent in Perl.
#
# Written by Russ Allbery <eagle@eyrie.org>
# Copyright 2014
#     The Board of Trustees of the Leland Stanford Junior University
#
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.

package Authen::Kerberos::Keytab;

use 5.010;
use strict;
use warnings;

use Authen::Kerberos;

our $VERSION;

# Set $VERSION in a BEGIN block for robustness.
BEGIN {
    $VERSION = '0.02';
}

1;

__END__

=for stopwords
Allbery keytab

=head1 NAME

Authen::Kerberos::Keytab - Kerberos API representation of a keytab

=head1 SYNOPSIS

    use Authen::Kerberos;

    my $krb5 = Authen::Kerberos->new;
    my $keytab = $krb5->keytab('FILE:/etc/krb5.keytab');
    my @entries = $keytab->entries;
    print 'First principal: ', $entries[0]->principal, "\n";

=head1 DESCRIPTION

An Authen::Kerberos::Keytab object wraps the Kerberos API
representation of an open keytab (key table).  A keytab holds zero or
more principal keys, usually in the form of a disk file.

=head1 INSTANCE METHODS

As with all Authen::Kerberos methods, an Authen::Kerberos::Exception
object will be thrown on any Kerberos error.

=over 4

=item entries()

In a scalar context, returns the number of entries in a keytab.  In an
array context, returns all of the entries of the keytab as
Authen::Kerberos::KeytabEntry objects.

=back

=head1 AUTHOR

Russ Allbery <eagle@eyrie.org>

=head1 SEE ALSO

L<Authen::Kerberos>, L<Authen::Kerberos::Exception>,
L<Authen::Kerberos::KeytabEntry>

=cut

# Wrapper class for Kerberos database entry objects.
#
# This class provides the Perl representation of a kadm5_principal_ent_t as
# used in the Kerberos kadmin API, which represents a principal entry in the
# Kerberos KDC database.  Most of the implementation is in the XS code
# underlying Authen::Kerberos::Kadmin.  This file provides documentation and
# some additional code that's easier to represent in Perl.
#
# Written by Russ Allbery <rra@cpan.org>
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

package Authen::Kerberos::Kadmin::Entry;

use 5.010;
use strict;
use warnings;

use Authen::Kerberos;
use Authen::Kerberos::Kadmin;

our $VERSION;

# Set $VERSION in a BEGIN block for robustness.
BEGIN {
    $VERSION = '0.02';
}

1;

__END__

=for stopwords
Allbery Heimdal KDB KDC libkadm5srv

=head1 NAME

Authen::Kerberos::Kadmin::Entry - Kerberos API representation of a KDB entry

=head1 SYNOPSIS

    use Authen::Kerberos::Kadmin;
    use Authen::Kerberos::Kadmin::Entry;

    my $kadmin = Authen::Kerberos::Kadmin->new(
        {
            realm            => 'EXAMPLE.COM',
            server           => 1,
        }
    );
    my $entry = $kadmin->get('test@EXAMPLE.COM');
    print 'Last password change: ', $entry->last_password_change, "\n";

=head1 REQUIREMENTS

Perl 5.10 or later, a Heimdal KDC, and the Heimdal libkadm5srv library.

=head1 DESCRIPTION

An Authen::Kerberos::Kadmin::Entry object wraps the Kerberos API
representation of a Kerberos database entry for a principal.  This is
returned by the get() method on an Authen::Kerberos::Kadmin object and can
be used to inspect, create, and modify Kerberos principal entries in the
database.

=head1 INSTANCE METHODS

As with all Authen::Kerberos methods, an Authen::Kerberos::Exception
object will be thrown on any Kerberos error.

=over 4

=item last_password_change

Returns the last password change time for this database entry in seconds
since UNIX epoch, or C<0> if there is no password change information
available.

=back

=head1 AUTHOR

Russ Allbery <rra@cpan.org>

=head1 SEE ALSO

L<Authen::Kerberos::Exception>, L<Authen::Kerberos::Kadmin>

=cut

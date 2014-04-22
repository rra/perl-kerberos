# Wrapper class for Kerberos keytab entry objects.
#
# This class provides the Perl representation of a krb5_keytab_entry structure
# as used in the Kerberos API.  Most of the implementation is in the XS code
# underlying Authen::Kerberos.  This file provides documentation and some
# additional code that's easier to represent in Perl.
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

package Authen::Kerberos::KeytabEntry;

use 5.010;
use strict;
use warnings;

use Authen::Kerberos;

our $VERSION;

# Set $VERSION in a BEGIN block for robustness.
BEGIN {
    $VERSION = '0.03';
}

1;

__END__

=for stopwords
Allbery KVNO keytab

=head1 NAME

Authen::Kerberos::KeytabEntry - Kerberos API representation of a keytab entry

=head1 SYNOPSIS

    use Authen::Kerberos;

    my $krb5 = Authen::Kerberos->new;
    my $keytab = $krb5->keytab('FILE:/etc/krb5.keytab');
    my @entries = $keytab->entries;
    print 'First principal: ', $entries[0]->principal, "\n";

=head1 DESCRIPTION

An Authen::Kerberos::KeytabEntry object wraps the Kerberos API
representation of an entry in a keytab (key table).  A keytab holds zero
or more entries, usually in the form of a disk file.  Each entry has a
key for a particular principal.

=head1 INSTANCE METHODS

As with all Authen::Kerberos methods, an Authen::Kerberos::Exception
object will be thrown on any Kerberos error.

=over 4

=item kvno()

Returns the KVNO (key version number) of this keytab entry.

=item principal()

Returns the principal whose key is stored in this entry, in the form of an
Authen::Kerberos::Principal object.

=item timestamp()

Returns the timestamp of this keytab entry as seconds since UNIX epoch.

=back

=head1 AUTHOR

Russ Allbery <rra@cpan.org>

=head1 SEE ALSO

L<Authen::Kerberos>, L<Authen::Kerberos::Exception>,
L<Authen::Kerberos::Keytab>

=cut

# Wrapper class for Kerberos principal objects.
#
# This class provides the Perl representation of a krb5_principal structure as
# used in the Kerberos API.  Most of the implementation is in the XS code
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

package Authen::Kerberos::Principal;

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
Allbery

=head1 NAME

Authen::Kerberos::Principal - Kerberos API representation of a principal name

=head1 SYNOPSIS

    use Authen::Kerberos;
    use Authen::Kerberos::Principal;

    my $krb5 = Authen::Kerberos->new;
    my $principal = $krb5->principal('test@EXAMPLE.COM');
    print "Principal: $principal\n";

=head1 DESCRIPTION

An Authen::Kerberos::Principal object wraps the Kerberos API
representation of a parsed principal name.

Normally, a user of the Authen::Kerberos module does not have to care
about the existence of this object.  APIs that take principals will take
either strings or Authen::Kerberos::Principal objects, and an
Authen::Kerberos::Principal object will be automatically converted to a
string when necessary.  Under the hood, this object holds a parsed form of
the principal that unambiguously separates the principal components and
realm without needing to use the escaping that the string display form
uses.

=head1 INSTANCE METHODS

As with all Authen::Kerberos methods, an Authen::Kerberos::Exception
object will be thrown on any Kerberos error.

=over 4

=item to_string()

Returns the string form (the display form) of the principal.  This method
will be automatically called if an Authen::Kerberos::Principal object is
interpolated into a string.  It may also be called directly to retrieve
the string form of the principal name.  Special characters in any
principal component, such as C<@> or C</>, will be escaped using the
normal Kerberos principal string encoding.

This is equivalent to the C function krb5_unparse_name().

=back

=head1 AUTHOR

Russ Allbery <rra@cpan.org>

=head1 SEE ALSO

L<Authen::Kerberos>, L<Authen::Kerberos::Exception>

=cut

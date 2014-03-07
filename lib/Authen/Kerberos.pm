# Perl bindings for the Kerberos API.
#
# This is the Perl boostrap file for the Authen::Kerberos module, nearly all
# of which is implemented in XS.  For the actual source, see Kerberos.xs.
# This file contains the bootstrap and export code and the documentation.
#
# Currently, this only provides an interface to the Heimdal libkrb5 library.
# This module will eventually become a level of indirection that can select
# from several XS modules to support both MIT Kerberos and Heimdal.
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

package Authen::Kerberos;

use 5.010;
use strict;
use warnings;

use base qw(DynaLoader);

use Exporter qw(import);

our $VERSION;

# Set $VERSION in a BEGIN block for robustness.
BEGIN {
    $VERSION = '0.02';
}

# The C code also creates some other types of objects and throws
# Authen::Kerberos::Exception objects, and callers expect to be able to call
# methods on those objects.  Load all of the Perl classes for the caller that
# provide additional object methods so that the caller doesn't have to
# remember to do so.
use Authen::Kerberos::Exception;
use Authen::Kerberos::Principal;

# Load the binary module.
bootstrap Authen::Kerberos $VERSION;

1;
__END__

=for stopwords
Allbery Heimdal keytabs libkrb5

=head1 NAME

Authen::Kerberos - Perl bindings for the Kerberos API

=head1 SYNOPSIS

    use Authen::Kerberos;

    my $krb5 = Authen::Kerberos->new;

=head1 REQUIREMENTS

Perl 5.10 or later and the Heimdal libkrb5 library.

=head1 DESCRIPTION

Authen::Kerberos provides Perl bindings for the Kerberos library API, used
to perform Kerberos operations such as acquiring tickets and examining
ticket caches and keytabs.

Currently, this module only supports Heimdal and only supports a small
fraction of the Kerberos library API.  More functionality will be added
later.

=head1 CLASS METHODS

All class methods throw Authen::Kerberos::Exception objects on any
Kerberos error.

=over 4

=item new([ARGS])

Create a new Authen::Kerberos object, which holds the internal library
state.  All further operations must be done with this object.

=back

=head1 INSTANCE METHODS

All class methods throw Authen::Kerberos::Exception objects on any
Kerberos error.

=over 4

=item keytab(KEYTAB)

Open the given keytab and return a new Authen::Kerberos::Keytab object for
it.  KEYTAB should be in the form I<type>:I<residual> where I<type> is one
of the keytab type identifiers recognized by the underlying Kerberos
library.  The most common type is C<FILE>, in which case I<residual> is a
path.

=item principal(NAME)

Convert the given principal name to an Authen::Kerberos::Principal object.
Normally there is no need to use this method since all Authen::Kerberos
APIs that take principal names will accept the string form of the principal
name and convert it internally.

=back

=head1 AUTHOR

Russ Allbery <eagle@eyrie.org>

=head1 SEE ALSO

L<Authen::Kerberos::Exception>

=cut

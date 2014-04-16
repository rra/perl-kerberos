# Perl bindings for the kadmin API.
#
# This is the Perl boostrap file for the Authen::Kerberos::Kadmin module,
# nearly all of which is implemented in XS.  For the actual source, see
# Kadmin.xs.  This file contains the bootstrap and export code and the
# documentation.
#
# Currently, this only provides an interface to the Heimdal libkadm5srv
# library.  This module will eventually become a level of indirection that can
# select from several XS modules to support both MIT Kerberos and Heimdal, and
# both the libkadm5clnt and libkadm5srv libraries.
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

package Authen::Kerberos::Kadmin;

use 5.010;
use strict;
use warnings;

use base qw(DynaLoader);

use Authen::Kerberos;
use Authen::Kerberos::Exception;
use Exporter qw(import);

our $VERSION;

# Set $VERSION in a BEGIN block for robustness.
BEGIN {
    $VERSION = '0.02';
}

# Load the binary module.
bootstrap Authen::Kerberos::Kadmin $VERSION;

1;
__END__

=for stopwords
Allbery Heimdal KDC kadmin libkadm5srv

=head1 NAME

Authen::Kerberos::Kadmin - Perl bindings for Kerberos administration

=head1 SYNOPSIS

    use Authen::Kerberos::Kadmin;

    my $kadmin = Authen::Kerberos::Kadmin->new(
        {
            password_quality => 1,
            realm            => 'EXAMPLE.COM',
            server           => 1,
        }
    );
    my ($principal, $password);
    $kadmin->chpass($principal, $password);

=head1 REQUIREMENTS

Perl 5.10 or later, a Heimdal KDC, and the Heimdal libkadm5srv library.

=head1 DESCRIPTION

Authen::Kerberos::Kadmin provides Perl bindings for the kadmin library
API, used to perform Kerberos administrative actions such as creating and
deleting principals or changing their keys or flags.

Currently, this module only supports Heimdal and only supports the server
mode, where the program is run on the KDC and makes changes directly to
the Kerberos KDC database.  It also only supports the password change
operation currently.  More functionality will be added later.

=head1 CLASS METHODS

All class methods throw exceptions on any error.

=over 4

=item new([ARGS])

Create a new Authen::Kerberos::Kadmin object, which holds the internal
library state.  All further operations must be done with this object.
ARGS, if present, is an anonymous hash of configuration options.
Supported options are:

=over 4

=item config_file

A Kerberos configuration file to use by preference.  This configuration
file will not replace the default system Kerberos configuration, but its
settings will override other settings.  It may be needed to configure such
things as password quality checking.

=item db_name

The name of or path to the Kerberos KDC database.  This option is only
used if the C<server> option is set to true.  If C<server> is true and
this option is not set, the compile-time or system-configured default will
be used.

Be warned that many versions of Heimdal completely ignore this parameter
and only use database paths configured in F<krb5.conf> or a file added via
C<config_file>.

=item password_quality

If set to a true value, the password quality check configuration will be
loaded and password quality checking will be enabled.  If set to a false
value or not present, passwords passed to chpass() will not be checked for
quality.  Be aware that, with a Heimdal KDC, password history is normally
done via the password quality interface, so not setting this option may
also lead to bypassing history checks.

=item realm

The Kerberos realm in which to take administrative actions.

=item server

If set to a true value, use the server kadmin API instead of the client
API.  This mode opens the Kerberos KDC database directly to make changes
instead of using the kadmin network protocol.  Currently, this option must
be present and set to a true value.

=item stash_file

The path to the stash file containing the master key for the Kerberos KDC
database.  This option is only used if the C<server> option is set to
true.  If C<server> is true and this option is not set, the compile-time
or system-configured default will be used.

Be warned that many versions of Heimdal completely ignore this parameter
and only use stash file paths configured in F<krb5.conf> or a file added
via C<config_file>.

=back

=back

=head1 INSTANCE METHODS

All instance methods throw Authen::Kerberos::Exception exceptions on any
error.

=over 4

=item chpass(PRINCIPAL, PASSWORD)

Change the Kerberos password for PRINCIPAL to PASSWORD.

If password quality checking is enabled via the C<password_quality>
parameter to the constructor, this method will fail and throw an exception
on any password quality check failure.

=back

=head1 AUTHOR

Russ Allbery <rra@cpan.org>

=head1 SEE ALSO

L<Authen::Kerberos::Exception>

=cut

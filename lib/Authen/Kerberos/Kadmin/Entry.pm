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
Allbery Heimdal KDB KDC libkadm5srv TGT TGS-REQ AS-REQ preauthentication
proxiable forwardable allow-kerberos4 disallow-all-tix disallow-dup-skey
disallow-forwardable disallow-proxiable disallow-svr disallow-tgt-based
pwchange-service requires-hw-auth requires-pre-auth requires-pw-change
support-desmd5 des-cbc-md5 DES enctypes new-princ

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

Many of these methods either return information from the Kerberos KDC
database (KDB) entry or set data if an argument to the method was given.
Any changes made this way only appear in the local object, not in the
actual KDC database, until this object is stored back in the database using
the modify() method of the Authen::Kerberos::Kadmin object.  That's also
when most errors will be reported.  When this object is passed to
modify(), everything that was updated in the object will be written to the
KDC database at the same time.

As with all Authen::Kerberos methods, an Authen::Kerberos::Exception
object will be thrown on any Kerberos error.

=over 4

=item attributes()

Returns the attributes of the principal entry.  In array context, they
will be returned as a list of strings.  In a scalar context, they will be
returned as one string, with attributes separated by a comma and a space
(the same format in which they're printed by C<kadmin examine>).  The
possible attribute strings and their meanings are:

=over 4

=item allow-digest

Digest authentication is allowed for this principal.

=item disallow-all-tix

All Kerberos authentication is prohibited for this principal.

=item disallow-forwardable

This principal cannot obtain forwardable tickets.

=item disallow-postdated

This principal cannot obtain postdated tickets (tickets with a start time
in the future).

=item disallow-proxiable

This principal cannot obtain proxiable tickets.  Proxiable tickets are a
weaker form of forwardable tickets that allows obtaining service tickets
with new addresses but not a new ticket-granting ticket with new
addresses.  They are not commonly used.

=item disallow-renewable

This principal cannot obtain renewable tickets.

=item disallow-svr

Service tickets will not be issued for this principal.  In other words,
this principal can authenticate and get tickets identifying itself, but
other principals cannot obtain service tickets to authenticate to this
principal.  This is typically used for user principals that do not operate
as services.

=item disallow-tgt-based

Service tickets will not be issued for this principal via a TGS-REQ (an
authentication using a TGT).  They can only be obtained via an AS-REQ (an
authentication using the user's long-term key directly).  This is
primarily used by services that should force a user authentication and not
permit authentication with cached tickets, such as the password change
service.

=item ok-as-delegate

This principal is trusted to accept delegated credentials.  Clients may
forward their tickets to this service identified by this principal so that
the service can authenticate to other services on their behalf.

=item pwchange-service

Clients are permitted to get a service ticket for this principal via an
AS-REQ even if the client's password has expired or the requires-pw-change
flag is set on the client's principal.  Generally this flag is only set on
the principal for the password change service, hence the name.

=item requires-hw-auth

This principal requires hardware authentication.  The meaning and effect
of this flag is not particularly well-defined, and it is not widely used.

=item requires-pre-auth

Preauthentication is required to obtain tickets as this principal.  This
should be set on all principals with weak keys (such as password-derived
keys) vulnerable to brute-force attacks, unless (even better) the KDC is
configured to always require preauthentication for any AS-REQ.

=item requires-pw-change

This principal can only obtain service tickets for a principal with the
pwchange-service attribute.  Setting this attribute is equivalent to
setting a password expiration time in the past for the principal, except
that once the password has been changed, the flag is cleared completely
instead of just pushing the password expiration time forward.

=item support-desmd5

This principal can accept des-cbc-md5 service tickets, which suffered from
a variety of protocol confusions and interoperability problems.  This flag
(along with the DES enctypes in general) is now obsolete.

=item trusted-for-delegation

This principal can obtain service tickets on behalf of principals other
than itself so that it can authenticate to other services as a user.

=item allow-kerberos4

=item disallow-dup-skey

=item new-princ

Not used, but included for completeness since the flags are defined.

=back

=item has_attribute(ATTRIBUTE)

Returns true if this database entry has that attribute set, false
otherwise.  ATTRIBUTE should be a string chosen from the list of valid
attributes as documented under the attributes() method.

=item last_password_change()

Returns the last password change time for this database entry in seconds
since UNIX epoch, or C<0> if there is no password change information
available.

=item password_expiration([TIME])

Returns the password expiration time for this database entry in seconds
since UNIX epoch, or C<0> if this principal does not have a password
expiration set.

If the TIME argument is given, sets the password expiration time to TIME,
which is in the same format, and returns the value that was set.

=back

=head1 AUTHOR

Russ Allbery <rra@cpan.org>

=head1 SEE ALSO

L<Authen::Kerberos::Exception>, L<Authen::Kerberos::Kadmin>

=cut

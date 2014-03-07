# Rich exception object for Kerberos operations.
#
# All Kerberos APIs, including ones on some subsidiary objects, throw an
# Authen::Kerberos::Exception on any failure of the underlying Kerberos API
# call.  This is a rich exception object that carries the Kerberos library
# error message, failure code, and additional information.  This Perl class
# defines the object and provides accessor methods to extract information from
# it.
#
# These objects are constructed in the static kadmin_croak function defined in
# Kadmin.xs.  Any changes to the code here should be reflected there and vice
# versa.
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

package Authen::Kerberos::Exception;

use 5.010;
use strict;
use warnings;

use overload '""' => \&to_string, 'cmp' => \&spaceship;

our $VERSION;

# Set $VERSION in a BEGIN block for robustness.
BEGIN {
    $VERSION = '0.02';
}

# There is intentionally no constructor.  This object is thrown by the
# Kerberos C API.

# Basic accessors.
sub function { my $self = shift; return $self->{function} }
sub message  { my $self = shift; return $self->{message} }
sub code     { my $self = shift; return $self->{code} }

# The cmp implmenetation converts the exception to a string and then compares
# it to the other argument.
#
# $self  - Authen::Kerberos::Exception object
# $other - The other object (generally a string) to which to compare it
# $swap  - True if the order needs to be swapped for a proper comparison
#
# Returns: -1, 0, or 1 per the cmp interface contract
sub spaceship {
    my ($self, $other, $swap) = @_;
    my $string = $self->to_string;
    if ($swap) {
        return ($other cmp $string);
    } else {
        return ($string cmp $other);
    }
}

# A full verbose message with all the information from the exception.
#
# $self - Authen::Kerberos::Exception object
#
# Returns: A string version of the exception information.
sub to_string {
    my ($self)   = @_;
    my $message  = $self->{message};
    my $function = $self->{function};
    my $file     = $self->{file};
    my $line     = $self->{line};

    # Construct the verbose message, trying to follow the normal Perl text
    # exception format.
    my $result = defined($function) ? "$function: $message" : $message;
    if (defined $line) {
        $result .= " at $file line $line";
    }
    return $result;
}

1;

__END__

=for stopwords
Allbery

=head1 NAME

Authen::Kerberos::Exception - Rich exception for Kerberos API method errors

=head1 SYNOPSIS

    my $kadmin = Authen::Kerberos::Kadmin->new;
    if (!eval { $kadmin->chpass('foo', 'password') }) {
        if (ref($@) eq 'Authen::Kerberos::Exception') {
            my $e = $@;
            print 'function: ', $e->function, "\n";
            print 'code: ', $e->code, "\n";
            print 'message: ', $e->message, "\n";
            print "$e\n";
            die $e->to_string;
        }
    }

=head1 DESCRIPTION

All Authen::Kerberos::Kadmin methods will throw an exception on error.
Exceptions produced by the underlying C API call will be represented by a
Authen::Kerberos::Exception object.

You can use this object like you would normally use $@, including printing
it out and doing string comparisons with it, and it will convert to the
string representation of the complete error message.  But you can also
access the structured data stored inside the exception by treating it as
an object and using the methods defined below.

=head1 METHODS

=over 4

=item code()

Returns the Kerberos status code for the exception.

=item function()

Returns the name of the Kerberos C API function that failed and caused the
exception to be raised.

=item message()

Returns the Kerberos error message.  This uses the underlying Kerberos API
calls to try to recover additional data about the cause of the error.

=item spaceship([STRING], [SWAP])

This method is called if the exception object is compared to a string via
cmp.  It will compare the given string to the verbose error message and
return the result.  If SWAP is set, it will reverse the order to compare
the given string to the verbose error.  (This is the normal interface
contract for an overloaded C<cmp> implementation.)

=item to_string()

This method is called if the exception is interpolated into a string.  It
can also be called directly to retrieve the default string form of the
exception.

=back

=head1 AUTHOR

Russ Allbery <eagle@eyrie.org>

=cut

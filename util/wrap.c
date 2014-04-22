/*
 * Utility functions for XS code to wrap Kerberos data structures.
 *
 * Provides helper functions to wrap Kerberos data structures in internal
 * representations so that we can easily generate appropriate Perl objects.
 *
 * Written by Russ Allbery <rra@cpan.org>
 * Copyright 2014
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include <EXTERN.h>
#include <perl.h>
#include <XSUB.h>

#include <portable/krb5.h>

#include <util/util.h>


/*
 * Given a krb5_principal, convert it to an Authen::Kerberos::Principal
 * object.  Make a copy of the principal so that it can be stored and used
 * independently of whatever object we generated it from.  Takes both the
 * context and the underlying Authen::Kerberos object so that we can stash the
 * latter in the created struct.
 */
Authen__Kerberos__Principal
akrb_wrap_principal(krb5_context ctx, SV *krb5, krb5_principal princ)
{
    krb5_principal copy;
    krb5_error_code code;
    Authen__Kerberos__Principal principal;

    code = krb5_copy_principal(ctx, princ, &copy);
    if (code != 0)
        akrb_croak(ctx, code, "krb5_copy_principal", FALSE);
    principal = malloc(sizeof(*principal));
    if (principal == NULL)
        croak("cannot allocate memory");
    principal->ctx = krb5;
    SvREFCNT_inc_simple_void_NN(principal->ctx);
    principal->principal = copy;
    return principal;
}

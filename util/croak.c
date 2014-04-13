/*
 * Utility functions for XS code to throw proper exceptions.
 *
 * All Authen::Kerberos modules throw Authen::Kerberos::Exception exceptions
 * on failure.  This is a helper function for XS code to construct such an
 * exception from an error code and additional information.
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


/*
 * Turn a Kerberos error into a Perl exception.  If the destroy argument is
 * true, free the Kerberos context after setting up the exception.  This is
 * used in cases where we're croaking inside the constructor.
 */
void
krb5_croak(krb5_context ctx, krb5_error_code code, const char *function,
           bool destroy)
{
    HV *hv;
    SV *rv;
    const char *message;

    hv = newHV();
    (void) hv_stores(hv, "code", newSViv(code));
    message = krb5_get_error_message(ctx, code);
    (void) hv_stores(hv, "message", newSVpv(message, 0));
    krb5_free_error_message(ctx, message);
    if (destroy)
        krb5_free_context(ctx);
    if (function != NULL)
        (void) hv_stores(hv, "function", newSVpv(function, 0));
    if (CopLINE(PL_curcop)) {
        (void) hv_stores(hv, "line", newSViv(CopLINE(PL_curcop)));
        (void) hv_stores(hv, "file", newSVpv(CopFILE(PL_curcop), 0));
    }
    rv = newRV_noinc((SV *) hv);
    sv_bless(rv, gv_stashpv("Authen::Kerberos::Exception", TRUE));
    sv_setsv(get_sv("@", TRUE), sv_2mortal(rv));
    croak(Nullch);
}

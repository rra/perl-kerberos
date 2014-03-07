/*
 * Utility functions for XS code to manipulate Kerberos contexts.
 *
 * Provides helper functions to manipulate Kerberos contexts in the
 * representation used inside Authen::Kerberos objects.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
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
 * Given an SV containing a krb5_context, return the underlying context
 * pointer for use with direct Kerberos calls.  Takes the type of object from
 * which the context is being retrieved for error reporting.
 */
krb5_context
krb5_context_from_sv(SV *ctx_sv, const char *type)
{
    IV ctx_iv;
    krb5_context ctx;

    if (ctx_sv == NULL)
        croak("no Kerberos context in %s object", type);
    ctx_iv = SvIV(ctx_sv);
    ctx = INT2PTR(krb5_context, ctx_iv);
    return ctx;
}

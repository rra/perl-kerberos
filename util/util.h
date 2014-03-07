/*
 * Extra utility functions for Kerberos Perl bindings.
 *
 * Prototypes for various utility functions used by multiple Kerberos XS
 * modules, collected together to avoid code duplication.
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

#ifndef UTIL_UTIL_H
#define UTIL_UTIL_H 1

#include <portable/macros.h>

#include <portable/krb5.h>      /* krb5_contxt, krb5_error_code */
#include <perl.h>               /* bool */

/* Used to check that an object argument to a function is not NULL. */
#define CROAK_NULL(o, t, f)                     \
    do {                                        \
        if ((o) == NULL)                        \
            croak(t " object is undef in " f);  \
    } while (0);
#define CROAK_NULL_SELF(o, t, f) CROAK_NULL((o), t, t "::" f)

BEGIN_DECLS

/* Default to a hidden visibility for all util functions. */
#pragma GCC visibility push(hidden)

/*
 * Given an SV that represents a Kerberos context, returns the underlying
 * context.  Takes the type of the object making this call for error
 * reporting.  Croaks if the SV is not valid.
 */
krb5_context krb5_context_from_sv(SV *, const char *type);

/*
 * Given a Kerberos context, an error code, and the Kerberos function that
 * failed, construct an Authen::Kerberos::Exception object and throw it using
 * croak.  The final boolean argument says whether to free the context before
 * calling croak.
 */
void krb5_croak(krb5_context, krb5_error_code, const char *function,
                bool destroy)
    __attribute__((__noreturn__));

/* Undo default visibility change. */
#pragma GCC visibility pop

END_DECLS

#endif /* UTIL_UTIL_H */

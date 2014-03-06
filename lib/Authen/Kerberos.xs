/* -*- c -*-
 * Perl bindings for the Kerberos API
 *
 * This is an XS source file, suitable for processing by xsubpp, that
 * generates Perl bindings for the Kerberos API (libkrb5).  It also provides
 * enough restructuring so that the C function calls can be treated as method
 * calls on a Kerberos context object.
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

#include <krb5.h>

/*
 * This typedefs are needed for xsubpp to work its magic with type translation
 * to Perl objects.  The krb5_context pointer is used as the Authen::Kerberos
 * object, wrapped in an SV and blessed.
 */
typedef krb5_context Authen__Kerberos;


/* XS code below this point. */

MODULE = Authen::Kerberos       PACKAGE = Authen::Kerberos

PROTOTYPES: DISABLE


Authen::Kerberos
new(class)
    const char *class
  PREINIT:
    krb5_context ctx;
    krb5_error_code code;
  CODE:
{
    code = krb5_init_context(&ctx);
    if (code != 0)
        krb5_croak(NULL, code, "krb5_init_context", FALSE);
    RETVAL = ctx;
}
  OUTPUT:
    RETVAL


void
DESTROY(self)
    Authen::Kerberos self
  CODE:
{
    if (self != NULL)
        krb5_free_context(self);
}

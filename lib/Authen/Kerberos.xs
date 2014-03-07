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

#include <glue/config.h>
#include <portable/krb5.h>
#include <portable/system.h>

#include <EXTERN.h>
#include <perl.h>
#include <XSUB.h>

#include <util/util.h>

/*
 * This typedefs are needed for xsubpp to work its magic with type translation
 * to Perl objects.  This strategy can only be used for objects that don't
 * need to stash a copy of the Kerberos context, such as the Kerberos context
 * object itself or ones where all methods on the object do not need a
 * context.
 */
typedef krb5_context Authen__Kerberos;

/*
 * Wrapper structs for additional data structures returned by the Kerberos
 * libraries.  We wrap the API data structure so that we can store a reference
 * to the Authen::Kerberos object (the Kerberos context), ensuring that the
 * Kerberos context is not freed before the secondary object and that the same
 * Kerberos context is used for all operations on that object.
 */
typedef struct {
    SV *ctx;
    krb5_keytab keytab;
} *Authen__Kerberos__Keytab;

typedef struct {
    SV *ctx;
    krb5_keytab_entry entry;
} *Authen__Kerberos__KeytabEntry;

typedef struct {
    SV *ctx;
    krb5_principal principal;
} *Authen__Kerberos__Principal;


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


Authen::Kerberos::Keytab
keytab(self, name)
    Authen::Kerberos self
    const char *name
  PREINIT:
    Authen__Kerberos__Keytab kt;
    krb5_error_code code;
    krb5_keytab keytab;
  CODE:
{
    CROAK_NULL_SELF(self, "Authen::Kerberos", "keytab_open");
    code = krb5_kt_resolve(self, name, &keytab);
    if (code != 0)
        krb5_croak(self, code, "krb5_kt_resolve", FALSE);
    kt = malloc(sizeof(*kt));
    if (kt == NULL)
        croak("cannot allocate memory");
    kt->keytab = keytab;
    kt->ctx = SvRV(ST(0));
    SvREFCNT_inc_simple_void_NN(kt->ctx);
    RETVAL = kt;
}
  OUTPUT:
    RETVAL


Authen::Kerberos::Principal
principal(self, name)
    Authen::Kerberos self
    const char *name
  PREINIT:
    krb5_error_code code;
    krb5_principal principal;
    Authen__Kerberos__Principal princ;
  CODE:
{
    CROAK_NULL_SELF(self, "Authen::Kerberos", "principal");
    code = krb5_parse_name(self, name, &principal);
    if (code != 0)
        krb5_croak(self, code, "krb5_parse_name", FALSE);
    princ = malloc(sizeof(*princ));
    if (princ == NULL)
        croak("cannot allocate memory");
    princ->principal = principal;
    princ->ctx = SvRV(ST(0));
    SvREFCNT_inc_simple_void_NN(princ->ctx);
    RETVAL = princ;
}
  OUTPUT:
    RETVAL


MODULE = Authen::Kerberos       PACKAGE = Authen::Kerberos::Keytab

void
DESTROY(self)
    Authen::Kerberos::Keytab self
  PREINIT:
    krb5_context ctx;
  CODE:
{
    if (self == NULL)
        return;
    ctx = krb5_context_from_sv(self->ctx, "Authen::Kerberos::Keytab");
    krb5_kt_close(ctx, self->keytab);
    SvREFCNT_dec(self->ctx);
    free(self);
}


void
entries(self)
    Authen::Kerberos::Keytab self
  PREINIT:
    krb5_context ctx;
    krb5_kt_cursor cursor;
    krb5_keytab_entry entry;
    Authen__Kerberos__KeytabEntry obj;
    krb5_error_code code;
    size_t count = 0;
  PPCODE:
{
    CROAK_NULL_SELF(self, "Authen::Kerberos::Keytab", "entries");
    ctx = krb5_context_from_sv(self->ctx, "Authen::Kerberos::Keytab");

    /* Start the cursor. */
    code = krb5_kt_start_seq_get(ctx, self->keytab, &cursor);
    if (code != 0)
        krb5_croak(ctx, code, "krb5_kt_start_seq_get", FALSE);

    /* For each entry, either count it or add it to the output stack. */
    code = krb5_kt_next_entry(ctx, self->keytab, &entry, &cursor);
    while (code != KRB5_KT_END) {
        count++;
        if (GIMME_V == G_ARRAY) {
            SV *obj;
            Authen__Kerberos__KeytabEntry wrapper;

            wrapper = malloc(sizeof(*wrapper));
            if (wrapper == NULL)
                croak("cannot allocate memory");
            wrapper->ctx = self->ctx;
            SvREFCNT_inc_simple_void_NN(wrapper->ctx);
            wrapper->entry = entry;
            obj = sv_newmortal();
            sv_setref_pv(obj, "Authen::Kerberos::KeytabEntry", wrapper);
            XPUSHs(obj);
        }
        code = krb5_kt_next_entry(ctx, self->keytab, &entry, &cursor);
    }

    /* Make sure everything was successful and close the cursor. */
    if (code != KRB5_KT_END)
        krb5_croak(ctx, code, "krb5_kt_next_entry", FALSE);
    krb5_kt_end_seq_get(ctx, self->keytab, &cursor);

    /* If we're in a scalar context, push the count. */
    if (GIMME_V != G_ARRAY) {
        ST(0) = newSViv(count);
        sv_2mortal(ST(0));
        XSRETURN(1);
    }
}


MODULE = Authen::Kerberos       PACKAGE = Authen::Kerberos::KeytabEntry

void
DESTROY(self)
    Authen::Kerberos::KeytabEntry self
  PREINIT:
    krb5_context ctx;
  CODE:
{
    if (self == NULL)
        return;
    ctx = krb5_context_from_sv(self->ctx, "Authen::Kerberos::KeytabEntry");
    krb5_kt_free_entry(ctx, &self->entry);
    SvREFCNT_dec(self->ctx);
    free(self);
}


krb5_kvno
kvno(self)
    Authen::Kerberos::KeytabEntry self
  CODE:
{
    CROAK_NULL_SELF(self, "Authen::Kerberos::KeytabEntry", "kvno");
    RETVAL = self->entry.vno;
}
  OUTPUT:
    RETVAL


Authen::Kerberos::Principal
principal(self)
    Authen::Kerberos::KeytabEntry self
  PREINIT:
    krb5_context ctx;
    krb5_principal princ;
    krb5_error_code code;
    Authen__Kerberos__Principal principal;
  CODE:
{
    CROAK_NULL_SELF(self, "Authen::Kerberos::KeytabEntry", "principal");
    ctx = krb5_context_from_sv(self->ctx, "Authen::Kerberos::KeytabEntry");
    code = krb5_copy_principal(ctx, self->entry.principal, &princ);
    if (code != 0)
        krb5_croak(ctx, code, "krb5_copy_principal", FALSE);
    principal = malloc(sizeof(*principal));
    if (principal == NULL)
        croak("cannot allocate memory");
    principal->ctx = self->ctx;
    SvREFCNT_inc_simple_void_NN(principal->ctx);
    principal->principal = princ;
    RETVAL = principal;
}
  OUTPUT:
    RETVAL


krb5_timestamp
timestamp(self)
    Authen::Kerberos::KeytabEntry self
  CODE:
{
    CROAK_NULL_SELF(self, "Authen::Kerberos::KeytabEntry", "timestamp");
    RETVAL = self->entry.timestamp;
}
  OUTPUT:
    RETVAL


MODULE = Authen::Kerberos       PACKAGE = Authen::Kerberos::Principal

void
DESTROY(self)
    Authen::Kerberos::Principal self
  PREINIT:
    krb5_context ctx;
  CODE:
{
    if (self == NULL)
        return;
    ctx = krb5_context_from_sv(self->ctx, "Authen::Kerberos::Principal");
    krb5_free_principal(ctx, self->principal);
    SvREFCNT_dec(self->ctx);
    free(self);
}


SV *
to_string(self, other = NULL, swap = 0)
    Authen::Kerberos::Principal self
    SV *other
    bool swap
  OVERLOAD: \"\"
  PREINIT:
    krb5_context ctx;
    krb5_error_code code;
    char *principal;
  CODE:
{
    CROAK_NULL_SELF(self, "Authen::Kerberos::Principal", "to_string");
    ctx = krb5_context_from_sv(self->ctx, "Authen::Kerberos::Principal");
    code = krb5_unparse_name(ctx, self->principal, &principal);
    if (code != 0)
        krb5_croak(ctx, code, "krb5_unparse_name", FALSE);
    RETVAL = newSVpv(principal, 0);
    krb5_free_unparsed_name(ctx, principal);
}
  OUTPUT:
    RETVAL

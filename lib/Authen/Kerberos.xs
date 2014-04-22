/* -*- c -*-
 * Perl bindings for the Kerberos API
 *
 * This is an XS source file, suitable for processing by xsubpp, that
 * generates Perl bindings for the Kerberos API (libkrb5).  It also provides
 * enough restructuring so that the C function calls can be treated as method
 * calls on a Kerberos context object.
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

#include <glue/config.h>
#include <portable/krb5.h>
#include <portable/system.h>

#include <stdlib.h>

#include <EXTERN.h>
#include <perl.h>
#include <XSUB.h>

#include <util/util.h>

/* Small helper macro to check if an SV is an object derived from a type. */
#define IS_OBJ(sv, type) (sv_isobject(sv) && sv_derived_from((sv), (type)))

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
    krb5_creds creds;
} *Authen__Kerberos__Creds;

typedef struct {
    SV *ctx;
    krb5_keytab keytab;
} *Authen__Kerberos__Keytab;

typedef struct {
    SV *ctx;
    krb5_keytab_entry entry;
} *Authen__Kerberos__KeytabEntry;


/*
 * Helper function to convert an argument to a keytab.  Accept either an
 * Authen::Kerberos::Keytab object or some other SV, which will be treated as
 * a string to use as the keytab name.
 */
static krb5_keytab
sv_to_keytab(SV *krb5, SV *sv)
{
    Authen__Kerberos__Keytab keytab;
    krb5_keytab kt;
    IV iv;

    /*
     * If the SV is not already an Authen::Kerberos::Keytab object, we have to
     * create a new krb5_keytab.  Do so by calling the normal constructor.
     * This allows us to return its contents and rely on Perl garbage
     * collection to free it later.
     *
     * Temporaries will be freed by the caller's FREETMPS/LEAVE.  Stay within
     * the caller's temporary frame.
     */
    if (!IS_OBJ(sv, "Authen::Kerberos::Keytab")) {
        int count;
        dSP;

        /* Set up the stack for the Perl call. */
        PUSHMARK(sp);
        XPUSHs(krb5);
        XPUSHs(sv);
        PUTBACK;

        /* Turn the scalar into a keytab using the regular method. */
        count = call_method("keytab", G_SCALAR);

        /* Retrieve the returned object from the stack. */
        SPAGAIN;
        if (count != 1)
            croak("Authen::Kerberos::keytab returned %d values", count);
        sv = POPs;
        PUTBACK;
    }

    /* Now extract the keytab from the object and return it. */
    iv = SvIV((SV *) SvRV(sv));
    keytab = INT2PTR(Authen__Kerberos__Keytab, iv);
    return keytab->keytab;
}


/*
 * The same as sv_to_keytab but for principals.  Return a krb5_principal given
 * either an Authen::Kerberos::Principal object or a string.
 */
static krb5_principal
sv_to_principal(SV *krb5, SV *sv)
{
    Authen__Kerberos__Principal principal;
    krb5_principal princ;
    IV iv;

    /*
     * If the SV is not already an Authen::Kerberos::Principal object, convert
     * it to one using the principal method, as in sv_to_keytab above.
     */
    if (!IS_OBJ(sv, "Authen::Kerberos::Principal")) {
        int count;
        dSP;

        /* Set up the stack for the Perl call. */
        PUSHMARK(sp);
        XPUSHs(krb5);
        XPUSHs(sv);
        PUTBACK;

        /* Turn the scalar into a principal using the regular method. */
        count = call_method("principal", G_SCALAR);

        /* Retrieve the returned object from the stack. */
        SPAGAIN;
        if (count != 1)
            croak("Authen::Kerberos::principal returned %d values", count);
        sv = POPs;
        PUTBACK;
    }

    /* Now extract the principal from the object and return it. */
    iv = SvIV((SV *) SvRV(sv));
    principal = INT2PTR(Authen__Kerberos__Principal, iv);
    return principal->principal;
}


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
        akrb_croak(NULL, code, "krb5_init_context", FALSE);
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


Authen::Kerberos::Creds
authenticate(self, args)
    Authen::Kerberos self
    HV *args
  PREINIT:
    krb5_context ctx;
    krb5_error_code code;
    krb5_keytab kt;
    krb5_principal princ;
    krb5_creds creds;
    krb5_get_init_creds_opt *opts;
    Authen__Kerberos__Keytab keytab;
    const char *realm, *path;
    const char *service = NULL;
    SV **value;
    IV iv;
  CODE:
{
    CROAK_NULL_SELF(self, "Authen::Kerberos", "authenticate");
    if (args == NULL)
        croak("no arguments given to Authen::Kerberos::authenticate");

    /* Retrieve the principal as which to authenticate. */
    value = hv_fetchs(args, "principal", 0);
    if (value == NULL || !SvOK(*value))
        croak("principal required in Authen::Kerberos::authenticate");
    princ = sv_to_principal(ST(0), *value);

    /*
     * Retrieve the keytab.  Currently, only keytab authentication is
     * supported.
     */
    value = hv_fetchs(args, "keytab", 0);
    if (value == NULL || !SvOK(*value))
        croak("keytab path required in Authen::Kerberos::authenticate");
    kt = sv_to_keytab(ST(0), *value);

    /* Get the target service, if specified. */
    value = hv_fetchs(args, "service", 0);
    if (value != NULL && SvOK(*value))
        service = SvPV_nolen(*value);

    /* Obtain credentials. */
    code = krb5_get_init_creds_opt_alloc(ctx, &opts);
    if (code != 0)
        akrb_croak(self, code, "krb5_get_init_creds_opt_alloc", FALSE);
    code = krb5_get_init_creds_keytab(self, &creds, princ, kt, 0, service,
                                      opts);
    krb5_get_init_creds_opt_free(ctx, opts);
    if (code != 0)
        akrb_croak(self, code, "krb5_get_init_creds_keytab", FALSE);

    /* Allocate the return data structure. */
    RETVAL = malloc(sizeof(*RETVAL));
    if (RETVAL == NULL) {
        krb5_free_cred_contents(self, &creds);
        croak("cannot allocate memory");
    }
    RETVAL->creds = creds;
    RETVAL->ctx = SvRV(ST(0));
    SvREFCNT_inc_simple_void_NN(RETVAL->ctx);
}
  OUTPUT:
    RETVAL


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
    CROAK_NULL_SELF(self, "Authen::Kerberos", "keytab");
    code = krb5_kt_resolve(self, name, &keytab);
    if (code != 0)
        akrb_croak(self, code, "krb5_kt_resolve", FALSE);
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
    krb5_principal princ;
    Authen__Kerberos__Principal principal;
  CODE:
{
    CROAK_NULL_SELF(self, "Authen::Kerberos", "principal");
    code = krb5_parse_name(self, name, &princ);
    if (code != 0)
        akrb_croak(self, code, "krb5_parse_name", FALSE);
    principal = malloc(sizeof(*principal));
    if (principal == NULL)
        croak("cannot allocate memory");
    principal->principal = princ;
    principal->ctx = SvRV(ST(0));
    SvREFCNT_inc_simple_void_NN(principal->ctx);
    RETVAL = principal;
}
  OUTPUT:
    RETVAL


MODULE = Authen::Kerberos       PACKAGE = Authen::Kerberos::Creds

void
DESTROY(self)
    Authen::Kerberos::Creds self
  PREINIT:
    krb5_context ctx;
  CODE:
{
    if (self == NULL)
        return;
    ctx = akrb_context_from_sv(self->ctx, "Authen::Kerberos::Creds");
    krb5_free_cred_contents(ctx, &self->creds);
    SvREFCNT_dec(self->ctx);
    free(self);
}


Authen::Kerberos::Principal
client(self)
    Authen::Kerberos::Creds self
  PREINIT:
    krb5_context ctx;
    krb5_principal princ;
    krb5_error_code code;
    Authen__Kerberos__Principal principal;
  CODE:
{
    CROAK_NULL_SELF(self, "Authen::Kerberos::Creds", "client");
    ctx = akrb_context_from_sv(self->ctx, "Authen::Kerberos::Creds");
    RETVAL = akrb_wrap_principal(ctx, self->ctx, self->creds.client);
}
  OUTPUT:
    RETVAL


Authen::Kerberos::Principal
server(self)
    Authen::Kerberos::Creds self
  PREINIT:
    krb5_context ctx;
    krb5_principal princ;
    krb5_error_code code;
    Authen__Kerberos__Principal principal;
  CODE:
{
    CROAK_NULL_SELF(self, "Authen::Kerberos::Creds", "server");
    ctx = akrb_context_from_sv(self->ctx, "Authen::Kerberos::Creds");
    RETVAL = akrb_wrap_principal(ctx, self->ctx, self->creds.server);
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
    ctx = akrb_context_from_sv(self->ctx, "Authen::Kerberos::Keytab");
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
    ctx = akrb_context_from_sv(self->ctx, "Authen::Kerberos::Keytab");

    /* Start the cursor. */
    code = krb5_kt_start_seq_get(ctx, self->keytab, &cursor);
    if (code != 0)
        akrb_croak(ctx, code, "krb5_kt_start_seq_get", FALSE);

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
        akrb_croak(ctx, code, "krb5_kt_next_entry", FALSE);
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
    ctx = akrb_context_from_sv(self->ctx, "Authen::Kerberos::KeytabEntry");
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
    ctx = akrb_context_from_sv(self->ctx, "Authen::Kerberos::KeytabEntry");
    code = krb5_copy_principal(ctx, self->entry.principal, &princ);
    if (code != 0)
        akrb_croak(ctx, code, "krb5_copy_principal", FALSE);
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
    ctx = akrb_context_from_sv(self->ctx, "Authen::Kerberos::Principal");
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
    ctx = akrb_context_from_sv(self->ctx, "Authen::Kerberos::Principal");
    code = krb5_unparse_name(ctx, self->principal, &principal);
    if (code != 0)
        akrb_croak(ctx, code, "krb5_unparse_name", FALSE);
    RETVAL = newSVpv(principal, 0);
    krb5_free_unparsed_name(ctx, principal);
}
  OUTPUT:
    RETVAL

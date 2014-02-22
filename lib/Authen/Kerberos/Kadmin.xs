/* -*- c -*-
 * Perl bindings for the kadmin API
 *
 * This is an XS source file, suitable for processing by xsubpp, that
 * generates Perl bindings for the Kerberos kadmin API (libkadm5srv or
 * libkadm5clnt).  It also provides enough restructuring so that the C
 * function calls can be treated as method calls on a kadmin connection
 * object.
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

#include <stdlib.h>
#include <string.h>

#include <EXTERN.h>
#include <perl.h>
#include <XSUB.h>

#include <krb5.h>
#include <kadm5/admin.h>

/*
 * Define a struct that wraps the kadmin API handle so that we can include
 * some other data structures that we need to use.
 */
typedef struct {
    void *handle;
    krb5_context ctx;
} *Authen__Kerberos__Kadmin;

/* Used to check that an object argument to a function is not NULL. */
#define CROAK_NULL(o, t, f)                     \
    do {                                        \
        if ((o) == NULL)                        \
            croak(t " object is undef in " f);  \
    } while (0);
#define CROAK_NULL_SELF(o, t, f) CROAK_NULL((o), t, t "::" f)


/*
 * Turn a Kerberos error into a Perl exception.  If the destroy argument is
 * true, free the Kerberos context after setting up the exception.  This is
 * used in cases where we're croaking inside the constructor.
 */
static void __attribute__((__noreturn__))
kadmin_croak(krb5_context ctx, krb5_error_code code, const char *function,
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


/* XS code below this point. */

MODULE = Authen::Kerberos::Kadmin       PACKAGE = Authen::Kerberos::Kadmin

PROTOTYPES: DISABLE


Authen::Kerberos::Kadmin
new(class, args)
    const char *class
    HV *args
  PREINIT:
    krb5_context ctx;
    krb5_error_code code;
    kadm5_config_params params;
    SV **value = NULL;
    void *handle;
    Authen__Kerberos__Kadmin self;
    bool quality = FALSE;
    const char *config_file;
    char **files;
  CODE:
{
    code = krb5_init_context(&ctx);
    if (code != 0)
        kadmin_croak(NULL, code, "krb5_init_context", FALSE);

    /* Parse the arguments to the function, if any. */
    memset(&params, 0, sizeof(params));
    if (args != NULL) {
        value = hv_fetchs(args, "server", 0);
        if (value == NULL || !SvTRUE(*value))
            croak("server mode required in Authen::Kerberos::Kadmin::new");

        /* The config file has to be set in the Kerberos context. */
        value = hv_fetchs(args, "config_file", 0);
        if (value != NULL) {
            config_file = SvPV_nolen(*value);
            code = krb5_prepend_config_files_default(config_file, &files);
            if (code != 0)
                kadmin_croak(ctx, code, "krb5_prepend_config_files_default",
                             TRUE);
            code = krb5_set_config_files(ctx, files);
            krb5_free_config_files(files);
            if (code != 0)
                kadmin_croak(ctx, code, "krb5_set_config_files", TRUE);
        }

        /* Set configuration parameters used by kadm5_init. */
        value = hv_fetchs(args, "db_name", 0);
        if (value != NULL) {
            params.dbname = SvPV_nolen(*value);
            params.mask |= KADM5_CONFIG_DBNAME;
        }
        value = hv_fetchs(args, "realm", 0);
        if (value != NULL) {
            params.realm = SvPV_nolen(*value);
            params.mask |= KADM5_CONFIG_REALM;
        }
        value = hv_fetchs(args, "stash_file", 0);
        if (value != NULL) {
            params.stash_file = SvPV_nolen(*value);
            params.mask |= KADM5_CONFIG_STASH_FILE;
        }

        /* Password quality we have to configure later. */
        value = hv_fetchs(args, "password_quality", 0);
        if (value != NULL && SvTRUE(*value))
            quality = TRUE;
    }

    /* Create the kadmin server handle. */
    code = kadm5_init_with_password_ctx(ctx, KADM5_ADMIN_SERVICE, NULL, NULL,
                                        &params,  KADM5_STRUCT_VERSION,
                                        KADM5_API_VERSION_2, &handle);
    if (code != 0)
        kadmin_croak(ctx, code, "kadm5_init_with_password_ctx", TRUE);

    /* Set up password quality checking if desired. */
    if (quality)
        kadm5_setup_passwd_quality_check(ctx, NULL, NULL);

    /* Flesh out our internal data structure. */
    self = malloc(sizeof(*self));
    if (self == NULL) {
        kadm5_destroy(handle);
        krb5_free_context(ctx);
        croak("cannot allocate memory");
    }
    self->ctx = ctx;
    self->handle = handle;
    RETVAL = self;
}
  OUTPUT:
    RETVAL


void
DESTROY(self)
    Authen::Kerberos::Kadmin self
  CODE:
{
    if (self == NULL)
        return;
    kadm5_destroy(self->handle);
    krb5_free_context(self->ctx);
    free(self);
}


void
chpass(self, principal, password)
    Authen::Kerberos::Kadmin self
    const char *principal
    const char *password
  PREINIT:
    krb5_error_code code;
    krb5_principal princ = NULL;
  CODE:
{
    code = krb5_parse_name(self->ctx, principal, &princ);
    if (code != 0)
        kadmin_croak(self->ctx, code, "krb5_parse_name", FALSE);
    code = kadm5_chpass_principal(self->handle, princ, password);
    krb5_free_principal(self->ctx, princ);
    if (code != 0)
        kadmin_croak(self->ctx, code, "kadm5_chpass_principal", FALSE);
    XSRETURN_YES;
}

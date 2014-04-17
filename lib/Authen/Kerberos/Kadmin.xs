/* -*- c -*-
 * Perl bindings for the kadmin API
 *
 * This is an XS source file, suitable for processing by xsubpp, that
 * generates Perl bindings for the Kerberos kadmin API (libkadm5srv or
 * libkadm5clnt).  It also provides enough restructuring so that the C
 * function calls can be treated as method calls on a kadmin connection
 * object.
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

#include <stdlib.h>
#include <string.h>

#include <EXTERN.h>
#include <perl.h>
#include <XSUB.h>

#include <portable/krb5.h>
#include <kadm5/admin.h>
#include <kadm5/kadm5_err.h>

#include <util/util.h>

/*
 * Define a struct that wraps the kadmin API handle so that we can include
 * some other data structures and configuration parameters that we need to
 * use.  Stores the corresponding Kerberos context as an Authen::Kerberos
 * object.
 */
typedef struct {
    void *handle;
    SV *ctx;
    bool quality;
} *Authen__Kerberos__Kadmin;

/*
 * Wrapper for a kadmin principal entry.  We want to store the underlying
 * Kerberos context, used to return some Kerberos data structures from the
 * principal, and the mask, which stores which parameters we modified.
 */
typedef struct {
    SV *handle;
    SV *ctx;
    uint32_t mask;
    kadm5_principal_ent_t ent;
} *Authen__Kerberos__Kadmin__Entry;


/*
 * Given an SV containing a kadmin handle, return the underlying handle
 * pointer for use with direct Kerberos calls.  Takes the type of object from
 * which the context is being retrieved for error reporting.
 */
static void *
handle_from_sv(SV *handle_sv, const char *type)
{
    IV handle_iv;
    void *handle;

    if (handle_sv == NULL)
        croak("no Kerberos kadmin handle in %s object", type);
    handle_iv = SvIV(handle_sv);
    handle = INT2PTR(void *, handle_iv);
    return handle;
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
    SV *sv;
  CODE:
{
    code = krb5_init_context(&ctx);
    if (code != 0)
        akrb_croak(NULL, code, "krb5_init_context", FALSE);

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
                akrb_croak(ctx, code, "krb5_prepend_config_files_default",
                           TRUE);
            code = krb5_set_config_files(ctx, files);
            krb5_free_config_files(files);
            if (code != 0)
                akrb_croak(ctx, code, "krb5_set_config_files", TRUE);
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
        akrb_croak(ctx, code, "kadm5_init_with_password_ctx", TRUE);

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
    sv = sv_setref_pv(sv_newmortal(), "Authen::Kerberos", ctx);
    self->ctx = SvRV(sv);
    SvREFCNT_inc_simple_void_NN(self->ctx);
    self->handle = handle;
    self->quality = quality;
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
    SvREFCNT_dec(self->ctx);
    free(self);
}


void
chpass(self, principal, password)
    Authen::Kerberos::Kadmin self
    const char *principal
    const char *password
  PREINIT:
    krb5_context ctx;
    krb5_error_code code;
    krb5_principal princ;
    krb5_data pwd_data;
    const char *reason;
  CODE:
{
    ctx = akrb_context_from_sv(self->ctx, "Authen::Kerberos::Kadmin");
    code = krb5_parse_name(ctx, principal, &princ);
    if (code != 0)
        akrb_croak(ctx, code, "krb5_parse_name", FALSE);

    /*
     * If configured to do quality checking, we need to do that manually,
     * since the server-side kadmin libraries never check quality.
     */
    if (self->quality) {
        pwd_data.data = (char *) password;
        pwd_data.length = strlen(password);
        reason = kadm5_check_password_quality(ctx, princ, &pwd_data);
        if (reason != NULL) {
            krb5_free_principal(ctx, princ);
            krb5_set_error_message(ctx, KADM5_PASS_Q_DICT, "%s", reason);
            akrb_croak(ctx, KADM5_PASS_Q_DICT, "kadm5_check_password_quality",
                       FALSE);
        }
    }

    /* Do the actual password change. */
    code = kadm5_chpass_principal(self->handle, princ, password);
    krb5_free_principal(ctx, princ);
    if (code != 0)
        akrb_croak(ctx, code, "kadm5_chpass_principal", FALSE);
    XSRETURN_YES;
}


Authen::Kerberos::Kadmin::Entry
get(self, principal)
    Authen::Kerberos::Kadmin self
    const char *principal
  PREINIT:
    krb5_context ctx;
    krb5_error_code code;
    krb5_principal princ;
    kadm5_principal_ent_t ent;
    uint32_t mask;
    Authen__Kerberos__Kadmin__Entry entry;
  CODE:
{
    ctx = akrb_context_from_sv(self->ctx, "Authen::Kerberos::Kadmin");
    ent = calloc(1, sizeof(*ent));
    if (ent == NULL)
        croak("cannot allocate memory");
    code = krb5_parse_name(ctx, principal, &princ);
    if (code != 0)
        akrb_croak(ctx, code, "krb5_parse_name", FALSE);

    /* By default, get everything except the keys. */
    mask = KADM5_PRINCIPAL_NORMAL_MASK;
    code = kadm5_get_principal(self->handle, princ, ent, mask);
    krb5_free_principal(ctx, princ);
    if (code != 0)
        akrb_croak(ctx, code, "kadm5_get_principal", FALSE);

    /* Build our internal representation. */
    entry = calloc(1, sizeof(*entry));
    if (entry == NULL)
        croak("cannot allocate memory");
    entry->handle = SvRV(ST(0));
    SvREFCNT_inc_simple_void_NN(entry->handle);
    entry->ctx = self->ctx;
    SvREFCNT_inc_simple_void_NN(entry->ctx);
    entry->ent = ent;
    RETVAL = entry;
}
  OUTPUT:
    RETVAL


void
list(self, pattern)
    Authen::Kerberos::Kadmin self
    const char *pattern
  PREINIT:
    krb5_context ctx;
    krb5_error_code code;
    char **princs;
    int count, i;
  PPCODE:
{
    CROAK_NULL_SELF(self, "Authen::Kerberos::Kadmin", "list");
    ctx = akrb_context_from_sv(self->ctx, "Authen::Kerberos::Kadmin");
    code = kadm5_get_principals(self->handle, pattern, &princs, &count);
    if (code != 0)
        akrb_croak(ctx, code, "kadm5_get_principals", FALSE);
    if (GIMME_V == G_ARRAY) {
        EXTEND(SP, count);
        for (i = 0; i < count; i++)
            PUSHs(sv_2mortal(newSVpv(princs[i], 0)));
    } else {
        ST(0) = newSViv(count);
        sv_2mortal(ST(0));
        XSRETURN(1);
    }
    kadm5_free_name_list(self->handle, princs, &count);
}


void
modify(self, entry)
    Authen::Kerberos::Kadmin self
    Authen::Kerberos::Kadmin::Entry entry
  PREINIT:
    void *handle;
    krb5_context ctx;
    krb5_error_code code;
  CODE:
{
    CROAK_NULL_SELF(self, "Authen::Kerberos::Kadmin", "modify");
    CROAK_NULL(entry, "Authen::Kerberos::Kadmin::Entry",
               "Authen::Kerberos::Kadmin::modify");
    ctx = akrb_context_from_sv(self->ctx, "Authen::Kerberos::Kadmin");
    code = kadm5_modify_principal(self->handle, entry->ent, entry->mask);
    if (code != 0)
        akrb_croak(ctx, code, "kadm5_modify_principal", FALSE);
    XSRETURN_YES;
}


MODULE = Authen::Kerberos::Kadmin    PACKAGE = Authen::Kerberos::Kadmin::Entry

void
DESTROY(self)
    Authen::Kerberos::Kadmin::Entry self
  PREINIT:
    void *handle;
  CODE:
{
    if (self == NULL)
        return;
    handle = handle_from_sv(self->handle, "Authen::Kerberos::Kadmin::Entry");
    kadm5_free_principal_ent(handle, self->ent);
    SvREFCNT_dec(self->handle);
    SvREFCNT_dec(self->ctx);
    free(self);
}


krb5_timestamp
last_password_change(self)
    Authen::Kerberos::Kadmin::Entry self
  CODE:
{
    CROAK_NULL_SELF(self, "Authen::Kerberos::Kadmin::Entry",
                    "last_password_change");
    RETVAL = self->ent->last_pwd_change;
}
  OUTPUT:
    RETVAL


krb5_timestamp
password_expiration(self, expiration = 0)
    Authen::Kerberos::Kadmin::Entry self
    krb5_timestamp expiration
  CODE:
{
    CROAK_NULL_SELF(self, "Authen::Kerberos::Kadmin::Entry",
                    "password_expiration");
    if (items > 1) {
        self->ent->pw_expiration = expiration;
        self->mask |= KADM5_PW_EXPIRATION;
    }
    RETVAL = self->ent->pw_expiration;
}
  OUTPUT:
    RETVAL

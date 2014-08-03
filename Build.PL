#!/usr/bin/perl
#
# Build script for the Authen::Kerberos distribution.
#
# Written by Russ Allbery <rra@cpan.org>
# Copyright 2014
#     The Board of Trustees of the Leland Stanford Junior University
#
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.

use 5.010;
use autodie;
use strict;
use warnings;

use Config::AutoConf;
use File::Basename qw(basename);
use File::Path qw(remove_tree);
use File::Spec;
use IPC::System::Simple qw(capturex);
use Module::Build;

# Check whether it's possible to link a program that uses a particular
# function.  This is written like a Config::AutoConf method and should ideally
# be incorporated into that module.  This macro caches its result in the
# ac_cv_func_FUNCTION variable.
#
# $self         - The Config::AutoConf state object
# $function     - The function to check for
# $found_ref    - Code reference to call if the function was found
# $notfound_ref - Code reference to call if the function wasn't found
#
# Returns: True if the function was found, false otherwise
sub check_func {
    my ($self, $function, $found_ref, $notfound_ref) = @_;
    $self = $self->_get_instance();

    # Build the name of the cache variable.
    my $cache_name = $self->_cache_name('func', $function);

    # Wrap the actual check in a closure so that we can use check_cached.
    my $check_sub = sub {
        my $have_func = $self->link_if_else($self->lang_call(q{}, $function));
        if ($have_func) {
            if (defined($found_ref) && ref($found_ref) eq 'CODE') {
                $found_ref->();
            }
        } else {
            if (defined($notfound_ref) && ref($notfound_ref) eq 'CODE') {
                $notfound_ref->();
            }
        }
        return $have_func;
    };

    # Run the check and cache the results.
    return $self->check_cached($cache_name, "for $function", $check_sub);
}

# The same as check_func, but takes a list of functions to look for and checks
# for each in turn.  Define HAVE_FUNCTION for each function that was found,
# and also run the $found_ref code each time a function was found.  Run the
# $notfound_ref code each time a function wasn't found.  Both code references
# are passed the name of the function that was found.
#
# $self          - The Config::AutoConf state object
# $functions_ref - Reference to an array of functions to check for
# $found_ref     - Code reference to call if a function was found
# $notfound_ref  - Code reference to call if a function wasn't found
#
# Returns: True if all functions were found, false otherwise.
sub check_funcs {
    my ($self, $functions_ref, $user_found_ref, $user_notfound_ref) = @_;
    $self = $self->_get_instance();

    # Build the code reference to run when a function was found.  This defines
    # a HAVE_FUNCTION symbol, plus runs the current $found_ref if there is
    # one.
    my $func_found_ref = sub {
        my ($function) = @_;

        # Generate the name of the symbol we'll define.
        my $have_func_name = 'HAVE_' . uc($function);
        $have_func_name =~ tr/_A-Za-z0-9/_/c;

        # Define the symbol.
        $self->define_var($have_func_name, 1,
            "Defined when $function is available");

        # Run the user-provided hook, if there is one.
        if (defined($user_found_ref) && ref($user_found_ref) eq 'CODE') {
            $user_found_ref->($function);
        }
    };

    # Go through the list of functions and call check_func for each one.  We
    # generate new closures for the found and not-found functions that pass in
    # the relevant function name.
    my $return = 1;
    for my $function (@{$functions_ref}) {
        my $found_ref    = sub { $func_found_ref->($function) };
        my $notfound_ref;
        if (defined($user_notfound_ref)) {
            $notfound_ref = sub { $user_notfound_ref->($function) };
        }
        $return &= check_func($self, $function, $found_ref, $notfound_ref);
    }
    return $return;
}

# Returns C code that includes the given headers.  Used to construct prologues
# for check functions.
#
# @headers - The headers to include
#
# Returns: C source as a string that includes those headers
sub include {
    my @headers = @_;
    my $result  = q{};
    for my $header (@headers) {
        $result .= "#include <$header>\n";
    }
    return $result;
}

# Probes the C compilation environment for the information required to build
# the Kerberos compatibility layer.  This should be a Perl equivalent of the
# m4/krb5.m4 Autoconf macros from rra-c-util, plus the additional probes
# needed for the compatibility layer for building the code.  Writes the
# results to glue/config.h and returns a list of extra C files to add to the
# module build.
#
# $build - The module build object, used to add additional libraries
#
# Returns: List of extra directories to add to the module build
#  Throws: Text exception if the module cannot be built in this environment
sub config_kerberos {
    my ($build) = @_;
    my $config = Config::AutoConf->new;

    # Checks needed for the generic portability layer.
    $config->check_default_headers;
    if (!$config->check_header('stdbool.h')) {
        $config->check_type('_Bool');
    }
    $config->check_type('ssize_t', undef, undef, include('sys/types.h'));

    # If the user passed extra flags into Build.PL, use them for probes.
    if ($build->extra_linker_flags) {
        my $flags = $build->extra_linker_flags;
        my @flags = ref($flags) ? @{$flags} : ($flags);
        $config->push_link_flags(@flags);
    }

    # Determine which Kerberos header to use.
    my $header = $config->check_headers('krb5.h', 'krb5/krb5.h');
    if (!defined($header)) {
        die "No Kerberos headers found (tried krb5.h and krb5/krb5.h)\n";
    }

    # Check for functions that are different between Heimdal and MIT.
    check_funcs($config, ['krb5_xfree']);
    my $includes = include($header) . $config->_default_includes;
    if ($config->check_decl('krb5_kt_free_entry', undef, undef, $includes)) {
        $config->define_var('HAVE_DECL_KRB5_KT_FREE_ENTRY',
            1, 'Defined when krb5_kt_free_entry is declared');
    }

    # Write out the configuration.
    $config->write_config_h('glue/config.h');
    return;
}

# Get the compiler and linker flags for Heimdal.  Currently, a new enough
# Heimdal to support pkg-config is required.
my $compiler_flags = capturex('pkg-config', '--cflags', 'heimdal-kadm-server');
my $linker_flags   = capturex('pkg-config', '--libs',   'heimdal-kadm-server');

# Basic package configuration.
my $build = Module::Build->new(
    module_name          => 'Authen::Kerberos',
    dist_abstract        => 'Perl bindings for Kerberos libraries',
    dist_author          => 'Russ Allbery <rra@cpan.org>',
    dist_version         => '0.03',
    license              => 'mit',
    recursive_test_files => 1,
    add_to_cleanup       => [qw(config.log cover_db glue/*.o util/*.o)],

    # XS configuration.
    #<<<
    c_source             => ['glue', 'util'],
    extra_compiler_flags => ['-I.', split(q{ }, $compiler_flags)],
    extra_linker_flags   => [split(q{ }, $linker_flags)],
    #>>>

    # Add additional package metadata.
    meta_merge => {
        resources => {
            repository =>
              'ssh://git.eyrie.org/srv/git/kerberos/perl-kerberos.git',
            bugtracker =>
'https://rt.cpan.org/Public/Dist/Display.html?Name=Authen-Kerberos',
        },
    },

    # Other package relationships.
    configure_requires => {
        'Config::AutoConf'    => 0,
        'IPC::System::Simple' => 0,
        'Module::Build'       => '0.3604',
        autodie               => 0,
        perl                  => '5.010',
    },
    requires => {
        autodie => 0,
        perl    => '5.010',
    },
);

# Create the directory that will be used for config.h and stub files.
remove_tree('glue');
mkdir('glue');

# Write out the config.h file and get the list of files to add to the build.
my @c_files = config_kerberos($build);

# We can't just add the C source files directly to the build for a couple of
# reasons.  First, Perl ships its own config.h, so we need to be sure we
# include our own instead of Perl's before building any source, since all of
# the files (copied from rra-c-util, so we don't want to change them) include
# config.h as the first action.  Second, Module::Build can only handle
# directories of supplemental files, not individual file names.
#
# We deal with both of these issues by creating stub files in a subdirectory
# named glue that include glue/config.h and then the actual C source file.
for my $file (@c_files) {
    my $glue_file = File::Spec->catfile('glue', basename($file));
    open(my $wrapper, '>', $glue_file);
    say {$wrapper} '#include <glue/config.h>'
      or die "Cannot write to $glue_file: $!\n";
    say {$wrapper} "#include <$file>"
      or die "Cannot write to $glue_file: $!\n";
    close($wrapper);
}

# Generate the build script.
$build->create_build_script;

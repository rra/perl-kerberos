#!/usr/bin/perl
#
# Build script for the Authen::Kerberos distribution.
#
# Written by Russ Allbery <rra@cpan.org>
# Copyright 2017 Russ Allbery <rra@cpan.org>
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
    if ($build->extra_compiler_flags) {
        my $flags = $build->extra_compiler_flags;
        my @flags = ref($flags) ? @{$flags} : ($flags);
        $config->push_compiler_flags(@flags);
    }
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
    $config->check_funcs(['krb5_xfree']);
    my $includes = include($header) . $config->_default_includes;
    if ($config->check_decl('krb5_kt_free_entry', { prologue => $includes })) {
        $config->define_var('HAVE_DECL_KRB5_KT_FREE_ENTRY',
            1, 'Defined when krb5_kt_free_entry is declared');
    }

    # Write out the configuration.
    $config->write_config_h('glue/config.h');
    return;
}

# Get the compiler and linker flags for Heimdal.  Currently, a new enough
# Heimdal to support pkg-config is required.
my ($compiler_flags, $linker_flags);
for my $package ('heimdal-krb5', 'heimdal-kadm-server') {
    $compiler_flags .= q{ } . capturex('pkg-config', '--cflags', $package);
    $linker_flags   .= q{ } . capturex('pkg-config', '--libs',   $package);
}
$compiler_flags =~ s{ ^ \s+ }{}xms;
$linker_flags =~ s{ ^ \s+ }{}xms;

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
        'Config::AutoConf'    => '0.307',
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

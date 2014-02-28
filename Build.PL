#!/usr/bin/perl
#
# Build script for the Authen::Kerberos distribution.
#
# Written by Russ Allbery <eagle@eyrie.org>
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

use IPC::System::Simple qw(capturex);
use Module::Build;

# Get the compiler and linker flags for Heimdal.  Currently, a new enough
# Heimdal to support pkg-config is required.
my $compiler_flags = capturex('pkg-config', '--cflags', 'heimdal-kadm-server');
my $linker_flags   = capturex('pkg-config', '--libs',   'heimdal-kadm-server');

# Basic package configuration.
my $build = Module::Build->new(
    module_name          => 'Authen::Kerberos',
    dist_abstract        => 'Perl bindings for Kerberos libraries',
    dist_author          => 'Russ Allbery <eagle@eyrie.org>',
    dist_version         => '0.01',
    license              => 'mit',
    recursive_test_files => 1,

    # XS configuration.
    extra_compiler_flags => [split(q{ }, $compiler_flags)],
    extra_linker_flags   => [split(q{ }, $linker_flags)],

    # Other package relationships.
    configure_requires => {
        'IPC::System::Simple' => 0,
        'Module::Build'       => '0.28',
        autodie               => 0,
        perl                  => '5.010',
    },
    requires => {
        autodie => 0,
        perl    => '5.010',
    },
);

# Generate the build script.
$build->create_build_script;

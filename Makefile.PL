use strict;
use warnings;
use inc::Module::Install;
use Module::Install::XSUtil; # for co-developpers
use constant DEBUG => 1;

use_ppport 3.19;
all_from 'lib/Test/AutoGenerator.pm';
requires_cplusplus;
cc_warnings;
cc_src_paths qw(src);
cc_include_paths qw(include);
cc_define qw();
makemaker_args->{CC} = 'g++';
makemaker_args->{LD} = 'g++';
makemaker_args->{LDLOADLIBS} .= ' -liconv';
my @ignore_warnings_options = qw(unused-variable unused-parameter);
makemaker_args->{CCFLAGS} .= join('', map { ' -Wno-' . $_ } @ignore_warnings_options);
if (DEBUG) {
    makemaker_args->{OPTIMIZE} = '-O0';
    makemaker_args->{CCFLAGS} = '-g3 ' . makemaker_args->{CCFLAGS};
}
WriteAll(check_nmake => 0);

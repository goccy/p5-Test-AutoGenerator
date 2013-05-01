package Test::AutoGenerator;
use 5.008008;
use strict;
use warnings;

require Exporter;

our @ISA = qw(Exporter);
our %EXPORT_TAGS = ( 'all' => [ qw() ] );
our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
our @EXPORT = qw(
);
our $VERSION = '0.01';
require XSLoader;
XSLoader::load(__PACKAGE__, $VERSION);

1;
__END__

=head1 NAME

Test::AutoGenerator - automatically generate perl test code

=head1 SYNOPSIS

1. paste under the code and run your program.

use Test::AutoGenerator;
my @libs = qw//;
Test::AutoGenerator->set_generated_library_name(\@libs);

2. automatically generated under your 't' directory

=head1 DESCRIPTION

=head1 AUTHOR

Masaaki Goshima E<lt>goccy54@gmail.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2013 by Masaaki Goshima

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.14 or,
at your option, any later version of Perl 5 you may have available.

=cut

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

AutoTest - automatically generate perl test code

=head1 SYNOPSIS

  use Test::AutoGenerator;


=head1 DESCRIPTION

Generate test code code from parsing source code.

=head1 AUTHOR

Masaaki Goshima E<lt>goccy54@gmail.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2012 by Masaaki Goshima

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.8 or,
at your option, any later version of Perl 5 you may have available.

=cut

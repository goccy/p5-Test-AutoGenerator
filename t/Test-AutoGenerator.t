use strict;
use warnings;
use Test::More;

BEGIN {
    use_ok('Test::AutoGenerator');
    my @libs = qw/A B/;
    Test::AutoGenerator->set_generated_library_name(\@libs);
};
use A;
my $a = A->new;
is($a->a, 3);

done_testing;

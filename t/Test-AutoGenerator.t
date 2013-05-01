use strict;
use warnings;
use Test::More;
BEGIN { use_ok('Test::AutoGenerator') };
use A;

my $a = A->new;
is($a->a, 3);

done_testing;

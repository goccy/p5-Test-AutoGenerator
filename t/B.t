use strict;
use warnings;
use Test::More;
use Test::MockObject;

use_ok('B');
subtest 'b' => sub {
    my $ret = B::b(bless ({}, 'B'));
    ok($ret == 2, 'B::b');
};

subtest 'new' => sub {
    my $ret = B::new("B");
    is_deeply($ret, bless ({}, 'B'), 'B::new');
};


done_testing();

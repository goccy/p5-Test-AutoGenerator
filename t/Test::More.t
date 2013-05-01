use strict;
use warnings;
use Test::More;
use Test::MockObject;

use_ok('Test::More');
subtest 'done_testing' => sub {
    Test::More::done_testing();
};

subtest 'is' => sub {
    Test::More::is(3, 3);
};


done_testing();

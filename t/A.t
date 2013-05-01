use strict;
use warnings;
use Test::More;
use Test::MockObject;

use_ok('A');
subtest 'a' => sub {
    Test::MockObject->fake_module('B',
        b => sub {
            2;
        }
    );
    my $ret = A::a(bless ({"b" => bless ({}, 'B')}, 'A'));
    ok($ret == 3, 'A::a');
};

subtest 'new' => sub {
    Test::MockObject->fake_module('B',
        new => sub {
            bless ({}, 'B');
        }
    );
    my $ret = A::new("A");
    is_deeply($ret, bless ({"b" => bless ({}, 'B')}, 'A'), 'A::new');
};


done_testing();

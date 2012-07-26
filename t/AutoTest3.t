use Test::More tests => 1;
unlink 't/AutoTest2.t','AutoTest1.pm';
ok(1, 'cleanup from AutoTest2.t');
#! /usr/bin/env perl
use strict;
use Test::More tests => 2;

my $src = << 'EOF';
package AutoTest1;

use warnings;
use strict;
use AutoTest;

sub h {
	return "hoge";
}

sub g {
	my $str = h(54);
	my $hash = {"a" => 12, "b" => 24};
	return (3, 4, 5, 6);
}

sub f {
	my @hash = g("args!");
	return 33;
}

my $a = f((1, 2, 3, 4));
EOF

SKIP: {
skip('/tmp/AutoTest1.t not writable', 2)
      unless (-d '/tmp' and -w '/tmp/');

my $script = 't/AutoTest1.pl';
my $t = '/tmp/AutoTest1.t';    # so far hardcoded
open F, ">", $script;
print F $src;
close F;
END { unlink $script, $t; }

my $X = $^X =~ m/\s/ ? qq{"$^X"} : $^X;
my $result = `$X -Mblib $script`;

ok(-f $t and -s $t, "$t created");
ok(system($X,'-c',$t) == 0, "$t parsable");

}

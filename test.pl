#! /opt/local/bin/perl5.12

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

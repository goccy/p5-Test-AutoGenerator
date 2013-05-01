package B;
use strict;
use warnings;

sub new {
    my $class = shift;
    return bless({}, $class);
}

sub b {
    return 2;
}

1;

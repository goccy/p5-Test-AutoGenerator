package A;
use strict;
use warnings;
use B;

sub new {
    my $class = shift;
    my $self = {
        b => B->new
    };
    return bless($self, $class);
}

sub a {
    my ($self) = @_;
    my $response = $self->{b}->b;
    return $response + 1;
}

1;

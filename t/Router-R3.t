# Before 'make install' is performed this script should be runnable with
# 'make test'. After 'make install' it should work as 'perl Router-R3.t'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

use strict;
use warnings;

use Test::More tests => 45;
BEGIN { use_ok('Router::R3') };

#########################

# Insert your test code below, the Test::More module is use()ed here so read
# its man page ( perldoc Test::More ) for help writing this test script.

sub test_match {
    my($r, $str) = @_;
    my($m, $capture) = $r->match($str);
    is($m, $_[2], "match $str");
    my $i = 3;
    while( $i < @_ ) {
        is($capture->{$_[$i]}, $_[$i+1], "capture $str $_[$i]");
        $i += 2;
    }
}

my @pattern = (
    '/abc' => 1,
    '/def/{x}' => 2,
    '/ghi/{x}/{y}' => 3,
    '/xyz/{a:\d{3}}/{b:\d+}' => 4,
);

sub test_all_match {
    my $r = shift;
    test_match($r, '/abc', 1);
    test_match($r, '/def/XX', 2, x => 'XX');
    test_match($r, '/def', undef);
    test_match($r, '/ghi/AA', undef);
    test_match($r, '/ghi/AA/BB', 3, x => 'AA', y => 'BB');
    test_match($r, '/xyz/123/4567', 4, a => '123', b => '4567');
    test_match($r, '/xyz/12/4567', undef);
    test_match($r, '/xyz/123/', undef);
    test_match($r, '/ghi/123/', undef);
}

test_all_match(Router::R3->new(@pattern));
test_all_match(Router::R3->new(\@pattern));
test_all_match(Router::R3->new({@pattern}));

eval { my $a = Router::R3->new("/abc/{a:(", 1) };
ok($@, "in-complete slug");

eval { my $a = Router::R3->new("/abc/{a:(}", 1) };
ok($@, "bad slug");

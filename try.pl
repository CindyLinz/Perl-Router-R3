#!/usr/bin/perl

use strict;
use warnings;

use Data::Dumper;

use Router::R3;

#Router::R3::test();
my $t = Router::R3::new_r3(
    '/foo/bar' => 2,
    '/zoo' => 1,
    '/bar' => 3,
    '/post/{id}' => 4,
    '/post2/{id:\d+}' => 5,
    '/post3/{idx:\d{3}}' => 6,
    '/post4/{idx:\d{3}}/{idy}' => 7,
);
my($a, $b) = Router::R3::match($t, '/post/XX-OO');
print "t=$t, a=$a, b=$b\n";
if( $b ) {
    local $Data::Dumper::Indent = 0;
    print Dumper($b), $/;
}

__END__

output:

t=REF(0xf30740), a=4, b=HASH(0xf307d0)
$VAR1 = {'id' => 'XX-OO'};


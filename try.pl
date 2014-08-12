#!/usr/bin/perl

use strict;
use warnings;

use lib qw(/home/cindy/perl5/lib/perl);
use Data::Dumper;

use Router::R3;

#Router::R3::test();
my $t = Router::R3->new(
    '/foo/bar' => 2,
    '/zoo' => 1,
    '/bar' => 3,
    '/post/{id}' => 4,
    '/post2/{id:\d+}' => 5,
    '/post3/{idx:\d{3}}' => 6,
    '/post4/{idx:\d{3}}/{idy:\d}' => 7,
);
#my $t = Router::R3->new(
#    '/a/' => 6,
#    '/a/{a}' => 7,
#);
my($a, $b) = $t->match('/post4/333/22');
print "t=$t, a=$a, b=$b\n";
if( $b ) {
    local $Data::Dumper::Indent = 0;
    print Dumper($b), $/;
}

__END__

output:

t=Router::R3=REF(0x23c27b8), a=7, b=HASH(0x23c27a0)
$VAR1 = {'idy' => '22','idx' => '333'};


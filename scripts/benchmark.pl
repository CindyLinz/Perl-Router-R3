#!/usr/bin/env perl
use lib 'lib';
use strict;
use warnings;
use Time::HiRes qw(time);
use Router::R3;
use Router::Boom;
use Router::Boom::Method;
use Router::Simple;
use HTTP::Router;
use Benchmark qw(:all);

$|++;


my @Benchmarks = (
    { desc => "plain string matching", path => '/corge/quux/bar' },
    { desc => "regexp string matching", path => '/post/2012/03' },
    { desc => "first charactar matching", path => '/' },
);

my $routes = require "scripts/routes.pl";

my $router_r3 = Router::R3->new($routes);

my $router_simple = Router::Simple->new();
for my $path ( keys %$routes )  {
    $router_simple->connect($path, { val => $routes->{ $path } } );
}


my $router_boom = Router::Boom->new();
for my $path ( keys %$routes )  {
    $router_boom->add($path, $routes->{ $path } );
}

my $http_router = HTTP::Router->new;
for my $path ( keys %$routes )  {
    $http_router->add_route($path => ( ));
}


my $N = 500000;



foreach my $b (@Benchmarks) {
    printf "Benchmarking '%s' by path '%s'\n", $b->{desc}, $b->{path};
    printf "===============================================================\n";

    my $path = $b->{path};

=pod
    my ($s, $d);

    printf "% 20s - ", "Router::R3";
    $s = time();
    for ( 1..$N ) {
        $router_r3->match($path);
    }
    $d = time() - $s;
    printf "%10.2f i/s\n", ($N / $d);

    printf "% 20s - ", "Router::Simple";
    $s = time();
    for ( 1..$N ) {
        $router_simple->match($path);
    }
    $d = time() - $s;
    printf "%10.2f i/s\n", ($N / $d);


    printf "% 20s - ", "HTTP::Router";
    $s = time();
    for ( 1..$N ) {
        $http_router->match($path);
    }
    $d = time() - $s;
    printf "%10.2f i/s\n", ($N / $d);


    printf "% 20s - ", "Router::Boom";
    $s = time();
    for ( 1..$N ) {
        $router_boom->match($path);
    }
    $d = time() - $s;
    printf "%10.2f i/s\n", ($N / $d);
=cut

    cmpthese(
        -1, {
            'Router::Simple'         => sub { $router_simple->match($path) },
            'Router::Boom'           => sub { $router_boom->match($path) },
            'Router::R3'             => sub { $router_r3->match($path) },
            'HTTP::Router'           => sub { $http_router->match($path) },
        }
    );
    printf "\n";
}


1;
__END__

Benchmark Result

https://gist.github.com/c9s/488d6fd4e53c34758559

Benchmarking 'plain string matching' by path '/corge/quux/bar'
===============================================================
                   Rate  HTTP::Router Router::Simple  Router::Boom    Router::R3
HTTP::Router      505/s            --           -88%         -100%         -100%
Router::Simple   4225/s          738%             --          -98%         -100%
Router::Boom   177535/s        35090%          4102%            --          -80%
Router::R3     877196/s       173773%         20660%          394%            --
 
Benchmarking 'regexp string matching' by path '/post/2012/03'
===============================================================
                   Rate  HTTP::Router Router::Simple  Router::Boom    Router::R3
HTTP::Router      383/s            --           -88%         -100%         -100%
Router::Simple   3199/s          734%             --          -97%          -99%
Router::Boom   107789/s        28007%          3269%            --          -67%
Router::R3     329098/s        85715%         10187%          205%            --
 
Benchmarking 'first charactar matching' by path '/'
===============================================================
                    Rate  HTTP::Router Router::Simple Router::Boom    Router::R3
HTTP::Router       179/s            --           -91%        -100%         -100%
Router::Simple    2036/s         1035%             --         -99%         -100%
Router::Boom    153597/s        85476%          7443%           --          -88%
Router::R3     1310719/s       730158%         64266%         753%            --

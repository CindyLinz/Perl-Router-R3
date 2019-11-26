# Before 'make install' is performed this script should be runnable with
# 'make test'. After 'make install' it should work as 'perl Router-R3.t'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

use strict;
use warnings;

use Test::More tests => 2;
BEGIN { use_ok('Router::R3') };

my %router;

sub _init {
    %router = (
        POST => Router::R3->new(
            '/api/v1/event/create' => sub {},
            '/api/v1/account/i/{i_account:\d+}/status' =>  sub {},
        ),
        GET => Router::R3->new(
             '/api/v1/account/i/{i_account:\d+}/status' => sub {},
             '/api/v1/account/{id}/status'              => sub {},
        ),
        DELETE => Router::R3->new(
             '/api/v1/group/i/{i_group:\d+}' => sub {},
             '/api/v1/group/{name}'          => sub {},
        ),
    );
}

_init();

ok( $router{POST}->match( '/api/v1/event/create' ) );
# ensure that there are no Segmentation Fault on exit

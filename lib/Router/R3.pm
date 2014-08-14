package Router::R3;

use 5.006;
use strict;
use warnings;
use Carp;

require Exporter;
use AutoLoader;

our $VERSION = '0.011001';

sub AUTOLOAD {
    # This AUTOLOAD is used to 'autoload' constants from the constant()
    # XS function.

    my $constname;
    our $AUTOLOAD;
    ($constname = $AUTOLOAD) =~ s/.*:://;
    croak "&Router::R3::constant not defined" if $constname eq 'constant';
    my ($error, $val) = constant($constname);
    if ($error) { croak $error; }
    goto &$AUTOLOAD;
}

require XSLoader;
XSLoader::load('Router::R3', $VERSION);

# Preloaded methods go here.

# Autoload methods go after =cut, and are processed by the autosplit program.

1;
__END__
# Below is stub documentation for your module. You'd better edit it!

=head1 NAME

Router::R3 - URL router library with high performance

=head1 SYNOPSIS

  use Router::R3;

  my $router = Router::R3->new(
    '/static/index.html' => 1,
    '/post/{id}' => 2,
    '/post_comment/{id:\d+}/{id2}' => 3,
  );

  my($match, $captures);
  ($match, $captures) = $router->match('/static/index.html'); # (1, {})
  ($match, $captures) = $router->match('/post/123'); # (2, { id => '123' })
  ($match, $captures) = $router->match('/post_comment/123/456'); # (3, { id => '123', id2 => '456' })
  ($match, $captures) = $router->match('/post_comment/xxx/456'); # ()  no match

  # or you can pass a hashref or an arrayref when Router::R3->new

  my $router = Router::R3->new(['/static', 1, '/post/{id}', 2]);
  my $router = Router::R3->new({'/static' => 1, '/post/{id}' => 2});

  # The latter one of each rule could be any perl scalar
  #  It'll be given to you when the rule is matched.
  #  It's better not to put anything which is treated as false here.

=head1 DESCRIPTION

This mod is a XS wrapper around a C library R3.

R3 is an URL router library with high performance, thus, it's implemented in C. It compiles your route paths into a prefix trie.

By using the constructed prefix trie in the start-up time, you can dispatch routes with efficiency.

=head2 PATTERN SYNTAX

  /blog/post/{id}        use [^/]+ regular expression by default.
  /blog/post/{id:\d+}    use `\d+` regular expression instead of default.
  /blog/post/{id:\d{2}}  use `\d{2}` regular expression instead of default.

=head1 INSTALLATION

Install from CPAN:

    $ cpanm Router::R3

Or from GitHub:

    $ git clone https://github.com/CindyLinz/Perl-Router-R3.git
    $ cd Perl-Router-R3
    $ cpanm -v --installdeps .

=head2 METHODS

=over 4

=item $router = Router::R3->new(...)

    The constructor

=item ($matched, \%captures) = $router->match($test_string)

    Match strings

=back

=head1 Benchmark

    Benchmarking 'plain string matching' by path '/corge/quux/bar'
    ===============================================================
                    Rate  HTTP::Router Router::Simple  Router::Boom    Router::R3
    HTTP::Router      203/s            --           -89%         -100%         -100%
    Router::Simple   1782/s          779%             --          -99%         -100%
    Router::Boom   168658/s        83094%          9365%            --          -82%
    Router::R3     954407/s       470684%         53461%          466%            --

    Benchmarking 'regexp string matching' by path '/post/2012/03'
    ===============================================================
                    Rate  HTTP::Router Router::Simple  Router::Boom    Router::R3
    HTTP::Router     1076/s            --           -88%          -99%         -100%
    Router::Simple   9309/s          765%             --          -91%          -97%
    Router::Boom   104387/s         9602%          1021%            --          -66%
    Router::R3     306925/s        28426%          3197%          194%            --

    Benchmarking 'first charactar matching' by path '/'
    ===============================================================
                        Rate  HTTP::Router Router::Simple Router::Boom    Router::R3
    HTTP::Router      3839/s            --           -87%         -98%         -100%
    Router::Simple   30545/s          696%             --         -83%          -98%
    Router::Boom    180555/s         4603%           491%           --          -88%
    Router::R3     1535999/s        39910%          4929%         751%            --


=head1 SEE ALSO

The original C version L<"github repository"|https://github.com/c9s/r3> by L<c9s|https://metacpan.org/author/CORNELIUS>

This mod's L<"github repository"|https://github.com/CindyLinz/Perl-Router-R3>
All the source files with this mod are in the Router-R3 directory.

=head1 AUTHOR

Cindy Wang (CindyLinz)

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2014 by Cindy Wang (CindyLinz)

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8 or,
at your option, any later version of Perl 5 you may have available.


=cut

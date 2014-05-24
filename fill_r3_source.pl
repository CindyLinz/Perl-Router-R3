#!/usr/bin/perl

use strict;
use warnings;

sub read_file {
    local $/;
    my($out, $f);
    open $f, $_[0];
    $out = <$f>;
    close $f;
    return $out;
}

sub write_file {
    my $f;
    open $f, ">$_[0]";
    print $f $_[1];
    close $f;
}

my $xs_code = read_file('R3.xs');

my $source_code = '';
$source_code =<<'END';
#define HAVE_STRNDUP
#define HAVE_STRDUP
END
for(qw(
    r3/include/r3_define.h
    r3/include/str_array.h
    r3/include/r3.h
    r3/include/r3_list.h
    r3/include/r3_str.h
    r3/include/zmalloc.h
    r3/src/edge.c
    r3/src/list.c
    r3/src/node.c
    r3/src/zmalloc.c
    r3/src/str.c
    r3/src/token.c
)) {
    $source_code .= "/******* $_ *******/\n";
    $source_code .= read_file($_);
}

$source_code =~ s!(#include\s+".*)!/* $1 */!g;
# $source_code =~ s!\b(strn?dup)\b!my_$1!g;

$xs_code =~ s!(__R3_SOURCE_SLOT_BEGIN__.*?\n)(.*?)([^\n]*?__R3_SOURCE_SLOT_END__)!$1$source_code$3!s;

write_file('R3.xs', $xs_code);

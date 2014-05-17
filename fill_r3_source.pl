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
for(qw(
    ../include/r3_define.h
    ../include/str_array.h
    ../include/r3.h
    ../include/r3_list.h
    ../include/r3_str.h
    ../src/edge.c
    ../src/list.c
    ../src/node.c
    ../src/str.c
    ../src/token.c
)) {
    $source_code .= "/******* $_ *******/\n";
    $source_code .= read_file($_);
}

$source_code =~ s!(#include\s+".*)!/* $1 */!g;
$source_code =~ s!\b(strn?dup)\b!my_$1!g;

$xs_code =~ s!(__R3_SOURCE_SLOT_BEGIN__.*?\n)(.*?)([^\n]*?__R3_SOURCE_SLOT_END__)!$1$source_code$3!s;

write_file('R3.xs', $xs_code);

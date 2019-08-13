#!/usr/bin/env perl

use v5.12;
use strict;
use warnings;

my $idgen = 0;
my $idmap = {};

print <<EOF;
#pragma once

#include <unistd.h>

struct io_op {
	int id;
	off_t start;
	off_t len;
};

struct io_op io_pattern[] = {
EOF

while (my $line = <>) {
	chomp($line);

	$line =~ s/^\s*//g;

	my ($start, $len, $id) = split /\s+/, $line;

	my $curid;
	if (exists $idmap->{$id}) {
		$curid = $idmap->{$id};
	} else {
		$curid = $idgen++;
		$idmap->{$id} = $curid;
	}

	$curid = $curid ^ 0xdeadbeef;

	printf "\t{%d, %d, %d},\n", $curid, $start, $len;
}

print "};\n";

printf "\n#define IO_ZERO_ID %d\n",
	($idmap->{'8a39d2abd3999ab73c34db2476849cddf303ce389b35826850f9a700589b4a90'} // $idgen);

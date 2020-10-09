#!/usr/bin/perl
open(FILE, "<$ARGV[0]") || die("Cannot open file $ARGV[0]\n\n");
binmode(FILE);
while (read FILE, $data, 1){
	$encode .= '%' . sprintf( "%02x", ord($data));
}

print $encode;

#!/usr/bin/perl
open(FILE, "<$ARGV[0]") || die("Cannot open file $ARGV[0]\n\n");
binmode(FILE);
$count = 0;
print "Shellcode:\n";
while (read FILE, $data, 1){
	print '\x' . sprintf( "%02x", ord($data));
	$count++;
}
close(FILE);
print "\n\n";
print "Length:$count\n";
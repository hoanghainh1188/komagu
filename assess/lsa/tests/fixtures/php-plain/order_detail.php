<?php
require_once 'inc/auth.php';
require_once 'inc/db.php';

$id = $_GET['id'];
$res = mysql_query("SELECT * FROM orders WHERE id = " . $id); // LSA-EXPECT:SQLI LSA-EXPECT:BOLA
$order = mysql_fetch_assoc($res);
echo htmlspecialchars($order['address']);

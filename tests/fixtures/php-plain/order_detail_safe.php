<?php
require_once 'inc/auth.php';
require_once 'inc/db.php';

$st = $pdo->prepare('SELECT * FROM orders WHERE id = ? AND user_id = ?'); // LSA-EXPECT:SAFE-SQL-NOFLAG LSA-EXPECT:SAFE-BOLA
$st->execute(array($_GET['id'], $_SESSION['user_id']));
$order = $st->fetch();
echo htmlspecialchars($order['address']);

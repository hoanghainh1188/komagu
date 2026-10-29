<?php
require_once '../inc/auth.php';
require_once '../inc/db.php';

$id = (int)$_POST['id'];
$stmt = $db->prepare("DELETE FROM users WHERE id = ?"); // LSA-EXPECT:BFLA
$stmt->execute(array($id));
header('Location: /admin/users.php');

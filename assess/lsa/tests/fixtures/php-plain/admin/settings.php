<?php
require_once '../inc/auth.php';
require_once '../inc/db.php';

if ($_SESSION['role'] !== 'admin') {
    http_response_code(404);
    exit;
}
$stmt = $db->prepare("UPDATE settings SET value = ? WHERE name = ?"); // LSA-EXPECT:SAFE-BFLA
$stmt->execute(array($_POST['value'], $_POST['name']));

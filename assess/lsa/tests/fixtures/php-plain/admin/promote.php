<?php
require_once '../inc/auth.php';
require_once '../inc/db.php';

if ($_POST['is_admin'] == '1') { // LSA-EXPECT:BFLA
    $stmt = $db->prepare("UPDATE users SET role = 'admin' WHERE id = ?");
    $stmt->execute(array((int)$_POST['uid']));
}

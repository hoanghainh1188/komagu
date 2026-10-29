<?php
require_once 'inc/auth.php';
require_once 'inc/db.php';

switch ($_GET['action']) {
    case 'view':
        $uid = (int)$_GET['uid'];
        $r = mysql_query("SELECT * FROM users WHERE id = " . $uid); // LSA-EXPECT:SAFE-SQL LSA-EXPECT:BOLA LSA-EXPECT:BFLA
        break;
    case 'delete':
        $id = $_POST['id'];
        mysql_query("DELETE FROM users WHERE id = $id"); // LSA-EXPECT:SQLI LSA-EXPECT:BOLA LSA-EXPECT:BFLA
        break;
}

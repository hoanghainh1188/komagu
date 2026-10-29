<?php
require_once 'inc/auth.php';
require_once 'inc/db.php';

$user = load_user($_SESSION['uid']);
foreach ($_POST as $field => $value) { // LSA-EXPECT:MASS
    $user->$field = $value;
}
$user->nickname = $_POST['nickname']; // LSA-EXPECT:SAFE-MASS
$user->role = $_POST['role']; // LSA-EXPECT:MASS
save_user($user);

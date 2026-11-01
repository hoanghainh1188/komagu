<?php
require_once 'inc/db.php';
$role = 'customer';
extract($_POST); // LSA-EXPECT:MASS
$stmt = $db->prepare("INSERT INTO users (email, name, role) VALUES (?, ?, ?)");
$stmt->execute(array($email, $name, $role));

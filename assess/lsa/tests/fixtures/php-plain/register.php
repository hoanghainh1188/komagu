<?php
require_once 'inc/db.php';

extract($_POST); // LSA-EXPECT:MASS
$stmt = $db->prepare("INSERT INTO users (email, name) VALUES (?, ?)");
$stmt->execute(array($email, $name));

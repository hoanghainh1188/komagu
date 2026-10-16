<?php
// Login check only. Does NOT check object ownership.
session_start();
if (empty($_SESSION['user_id'])) {
    header('Location: /login.php');
    exit;
}

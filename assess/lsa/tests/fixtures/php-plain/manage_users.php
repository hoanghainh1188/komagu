<?php
require_once 'inc/auth.php';
require_once 'inc/db.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $stmt = $db->prepare("DELETE FROM users WHERE id = ?"); // LSA-EXPECT:BFLA
    $stmt->execute(array((int)$_POST['id']));
}
?>
<ul>
<?php if ($_SESSION['role'] == 'admin'): ?><li><a href="/manage_users.php">Delete users</a></li><?php endif; ?>
</ul>

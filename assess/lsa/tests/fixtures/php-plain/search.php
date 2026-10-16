<?php
require_once 'inc/auth.php';
require_once 'inc/db.php';

$kw = addslashes($_GET['q']);
$sort = $_GET['sort'];
$sql = "SELECT id, name FROM products WHERE 1=1";
$sql .= " AND name LIKE '%" . $kw . "%'"; // LSA-EXPECT:SQLI
$sql .= " ORDER BY " . $sort; // LSA-EXPECT:SQLI
$sql2 = "SELECT * FROM products WHERE status = '" . STATUS_ACTIVE . "'";
$res = mysql_query($sql);
$q = <<<SQL
SELECT * FROM products
WHERE category = '{$_GET['cat']}' -- LSA-EXPECT:SQLI
SQL;
$res2 = mysql_query($q);
$total = mysql_query('SELECT COUNT(*) FROM products'); // LSA-EXPECT:SAFE-SQL-NOFLAG

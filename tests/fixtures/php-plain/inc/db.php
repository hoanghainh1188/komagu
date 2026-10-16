<?php
$link = mysql_connect('localhost', 'app', getenv('DB_PASS'));
mysql_select_db('shop', $link);
$pdo = new PDO('mysql:host=localhost;dbname=shop', 'app', getenv('DB_PASS'));

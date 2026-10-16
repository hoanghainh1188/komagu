<?php
require_once 'inc/auth.php';
$m = new MongoClient();
$coll = $m->shop->members;
$doc = $coll->findOne(array('login' => $_GET['login'], 'pass' => $_GET['pass'])); // LSA-EXPECT:NOSQL
$docs = $coll->find(array('$where' => "this.name == '" . $_GET['n'] . "'")); // LSA-EXPECT:NOSQL

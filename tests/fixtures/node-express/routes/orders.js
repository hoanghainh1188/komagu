var express = require('express');
var router = express.Router();
var db = require('../db');
var Order = require('../models/order');

function ensureLoggedIn(req, res, next) { if (!req.user) return res.redirect('/login'); next(); }

router.get('/orders/:id', ensureLoggedIn, function (req, res) {
  Order.findById(req.params.id, function (err, order) { res.json(order); }); // LSA-EXPECT:BOLA
});

router.get('/orders/:id/mine', ensureLoggedIn, function (req, res) {
  Order.findOne({ _id: req.params.id, owner: req.user._id }, function (err, o) { res.json(o); }); // LSA-EXPECT:SAFE-BOLA
});

router.get('/reports', ensureLoggedIn, function (req, res) {
  db.query("SELECT * FROM reports WHERE month = '" + req.query.month + "'", function (e, rows) { res.json(rows); }); // LSA-EXPECT:SQLI
});

router.post('/login', function (req, res) {
  db.collection('users').findOne(req.body, function (e, u) { res.json(!!u); }); // LSA-EXPECT:NOSQL
});

router.get('/search', ensureLoggedIn, function (req, res) {
  db.collection('items').find({ $where: "this.name == '" + req.query.n + "'" }).toArray(function (e, r) { res.json(r); }); // LSA-EXPECT:NOSQL
});

router.get('/stats', function (req, res) {
  db.query(`SELECT COUNT(*) AS n FROM orders WHERE shop_id = ${req.query.shop}`, function (e, r) { res.json(r); }); // LSA-EXPECT:SQLI LSA-EXPECT:BOLA
});

module.exports = router;

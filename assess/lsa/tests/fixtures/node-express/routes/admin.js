var express = require('express');
var router = express.Router();
var User = require('../models/user');

function ensureLoggedIn(req, res, next) { if (!req.user) return res.redirect('/login'); next(); }
function requireAdmin(req, res, next) { if (req.user.role !== 'admin') return res.sendStatus(404); next(); }

router.post('/admin/users/:id/delete', ensureLoggedIn, function (req, res) {
  User.deleteOne({ _id: req.params.id }, function () { res.sendStatus(204); }); // LSA-EXPECT:BFLA
});

router.post('/admin/users/:id/ban', ensureLoggedIn, requireAdmin, function (req, res) {
  User.updateOne({ _id: req.params.id }, { banned: true }, function () { res.sendStatus(204); }); // LSA-EXPECT:SAFE-BFLA
});

router.get('/reports/export', ensureLoggedIn, function (req, res) {
  if (req.query.isAdmin === 'true') { res.json([]); } // LSA-EXPECT:BFLA
});

module.exports = router;

var express = require('express');
var router = express.Router();
var User = require('../models/user');

function ensureLoggedIn(req, res, next) { if (!req.user) return res.redirect('/login'); next(); }

router.put('/profile', ensureLoggedIn, function (req, res) {
  User.findByIdAndUpdate(req.user._id, req.body, function (e, u) { res.json(u); }); // LSA-EXPECT:MASS
});

router.put('/profile/name', ensureLoggedIn, function (req, res) {
  User.findByIdAndUpdate(req.user._id, { name: req.body.name }, function (e, u) { res.json(u); }); // LSA-EXPECT:SAFE-MASS
});

router.post('/signup', function (req, res) {
  var user = new User(req.body); // LSA-EXPECT:MASS
  user.save(function () { res.sendStatus(201); });
});

router.post('/profile/settings', ensureLoggedIn, function (req, res) {
  var prefs = Object.assign({}, req.user.prefs, { theme: req.body.theme }); // LSA-EXPECT:SAFE-MASS
  res.json(prefs);
});

module.exports = router;

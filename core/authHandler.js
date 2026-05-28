var db = require('../models')
var bCrypt = require('bcrypt')
var crypto = require('crypto')

// In-memory token store: { token: { login, expiresAt } }
var passwordResetTokens = {}

// Periodically purge expired tokens to prevent unbounded memory growth
setInterval(function () {
	var now = Date.now()
	Object.keys(passwordResetTokens).forEach(function (token) {
		if (passwordResetTokens[token].expiresAt <= now) {
			delete passwordResetTokens[token]
		}
	})
}, 3600000) // run every hour

module.exports.isAuthenticated = function (req, res, next) {
	if (req.isAuthenticated()) {
		req.flash('authenticated', true)
		return next();
	}
	res.redirect('/login');
}

module.exports.isNotAuthenticated = function (req, res, next) {
	if (!req.isAuthenticated())
		return next();
	res.redirect('/learn');
}

module.exports.forgotPw = function (req, res) {
	if (req.body.login) {
		db.User.find({
			where: {
				'login': req.body.login
			}
		}).then(user => {
			if (user) {
				var token = crypto.randomBytes(32).toString('hex')
				passwordResetTokens[token] = {
					login: req.body.login,
					expiresAt: Date.now() + 3600000 // 1 hour
				}
				// Send reset link via email happens here
				req.flash('info', 'Check email for reset link')
				res.redirect('/login')
			} else {
				req.flash('danger', "Invalid login username")
				res.redirect('/forgotpw')
			}
		})
	} else {
		req.flash('danger', "Invalid login username")
		res.redirect('/forgotpw')
	}
}

module.exports.resetPw = function (req, res) {
	if (req.query.login && req.query.token) {
		var tokenData = passwordResetTokens[req.query.token]
		if (tokenData && tokenData.login === req.query.login && tokenData.expiresAt > Date.now()) {
			res.render('resetpw', {
				login: req.query.login,
				token: req.query.token
			})
		} else {
			req.flash('danger', "Invalid or expired reset token")
			res.redirect('/forgotpw')
		}
	} else {
		req.flash('danger', "Non Existant login username")
		res.redirect('/forgotpw')
	}
}

module.exports.resetPwSubmit = function (req, res) {
	if (req.body.password && req.body.cpassword && req.body.login && req.body.token) {
		if (req.body.password == req.body.cpassword) {
			var tokenData = passwordResetTokens[req.body.token]
			if (tokenData && tokenData.login === req.body.login && tokenData.expiresAt > Date.now()) {
				db.User.find({
					where: {
						'login': req.body.login
					}
				}).then(user => {
					if (user) {
						delete passwordResetTokens[req.body.token]
						user.password = bCrypt.hashSync(req.body.password, bCrypt.genSaltSync(10), null)
						user.save().then(function () {
							req.flash('success', "Password successfully reset")
							res.redirect('/login')
						})
					} else {
						req.flash('danger', "Invalid login username")
						res.redirect('/forgotpw')
					}
				})
			} else {
				req.flash('danger', "Invalid or expired reset token")
				res.redirect('/forgotpw')
			}
		} else {
			req.flash('danger', "Passwords do not match")
			res.render('resetpw', {
				login: req.body.login,
				token: req.body.token
			})
		}

	} else {
		req.flash('danger', "Invalid request")
		res.redirect('/forgotpw')
	}
}
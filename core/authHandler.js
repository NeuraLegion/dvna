var db = require('../models')
var bCrypt = require('bcrypt')
var crypto = require('crypto')

// FIX: Store reset tokens in memory (production should use DB/Redis with expiry)
var resetTokens = {}

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
				// FIX: Use cryptographically secure random token instead of md5(username)
				var token = crypto.randomBytes(32).toString('hex')
				var expiry = Date.now() + (60 * 60 * 1000) // 1 hour expiry
				resetTokens[req.body.login] = { token: token, expiry: expiry }
				// In production: send token via email
				// For dev: log token (would be sent via email in production)
				console.log('Password reset token for', req.body.login, ':', token)
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
	if (req.query.login) {
		db.User.find({
			where: {
				'login': req.query.login
			}
		}).then(user => {
			if (user) {
				// FIX: Validate token against secure stored token with expiry check
				var storedReset = resetTokens[req.query.login]
				if (storedReset && storedReset.token === req.query.token && Date.now() < storedReset.expiry) {
					res.render('resetpw', {
						login: req.query.login,
						token: req.query.token
					})
				} else {
					req.flash('danger', "Invalid or expired reset token")
					res.redirect('/forgotpw')
				}
			} else {
				req.flash('danger', "Invalid login username")
				res.redirect('/forgotpw')
			}
		})
	} else {
		req.flash('danger', "Non Existant login username")
		res.redirect('/forgotpw')
	}
}

module.exports.resetPwSubmit = function (req, res) {
	if (req.body.password && req.body.cpassword && req.body.login && req.body.token) {
		if (req.body.password == req.body.cpassword) {
			db.User.find({
				where: {
					'login': req.body.login
				}
			}).then(user => {
				if (user) {
					// FIX: Validate against secure stored token
					var storedReset = resetTokens[req.body.login]
					if (storedReset && storedReset.token === req.body.token && Date.now() < storedReset.expiry) {
						user.password = bCrypt.hashSync(req.body.password, bCrypt.genSaltSync(10), null)
						user.save().then(function () {
							// Invalidate token after use
							delete resetTokens[req.body.login]
							req.flash('success', "Password successfully reset")
							res.redirect('/login')
						})
					} else {
						req.flash('danger', "Invalid or expired reset token")
						res.redirect('/forgotpw')
					}
				} else {
					req.flash('danger', "Invalid login username")
					res.redirect('/forgotpw')
				}
			})
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
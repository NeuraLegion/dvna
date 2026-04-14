var router = require('express').Router()
var vulnDict = require('../config/vulns')
var authHandler = require('../core/authHandler')

function setCorsHeader (req, res) {
	var allowedOrigins = [
		process.env.CORS_ALLOWED_ORIGIN
	].filter(Boolean)

	if (allowedOrigins.length === 0) {
		return
	}

	var origin = req.headers.origin
	if (allowedOrigins.indexOf(origin) !== -1) {
		res.setHeader('Access-Control-Allow-Origin', origin)
		res.setHeader('Vary', 'Origin')
	}
}

module.exports = function (passport) {
	router.get('/', authHandler.isAuthenticated, function (req, res) {
		res.redirect('/learn')
	})

	router.get('/login', authHandler.isNotAuthenticated, function (req, res) {
		res.render('login')
	})

	router.get('/learn/vulnerability/:vuln', authHandler.isAuthenticated, function (req, res) {
		setCorsHeader(req, res)
		res.render('vulnerabilities/layout', {
			vuln: req.params.vuln,
			vuln_title: vulnDict[req.params.vuln],
			vuln_scenario: req.params.vuln + '/scenario',
			vuln_description: req.params.vuln + '/description',
			vuln_reference: req.params.vuln + '/reference',
			vulnerabilities: vulnDict
		}, function (err, html) {
			if (err) {
				console.log(err)
				res.status(404).send('404')
			} else {
				res.send(html)
			}
		})
	})

	router.get('/learn', authHandler.isAuthenticated, function (req, res) {
		setCorsHeader(req, res)
		res.render('learn', { vulnerabilities: vulnDict })
	})

	router.get('/register', authHandler.isNotAuthenticated, function (req, res) {
		res.render('register')
	})

	router.get('/logout', function (req, res) {
		var clearSessionCookie = function () {
			res.clearCookie('connect.sid', { httpOnly: true, secure: true })
			res.redirect('/')
		}

		if (req.logout) {
			req.logout(function () {
				if (req.session) {
					req.session.destroy(clearSessionCookie)
				} else {
					clearSessionCookie()
				}
			})
		} else {
			if (req.session) {
				req.session.destroy(clearSessionCookie)
			} else {
				clearSessionCookie()
			}
		}
	})

	router.get('/forgotpw', function (req, res) {
		res.render('forgotpw')
	})

	router.get('/resetpw', authHandler.resetPw)

	router.post('/login', passport.authenticate('login', {
		successRedirect: '/learn',
		failureRedirect: '/login',
		failureFlash: true
	}))

	router.post('/register', passport.authenticate('signup', {
		successRedirect: '/learn',
		failureRedirect: '/register',
		failureFlash: true
	}))

	router.post('/forgotpw', authHandler.forgotPw)

	router.post('/resetpw', authHandler.resetPwSubmit)

	return router
}

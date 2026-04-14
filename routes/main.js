var router = require('express').Router()
var vulnDict = require('../config/vulns')
var authHandler = require('../core/authHandler')

function clearSessionCookie(req, res) {
	res.clearCookie('connect.sid', {
		path: '/',
		httpOnly: true,
		secure: process.env.NODE_ENV === 'production' ? true : 'auto',
		sameSite: 'lax'
	})
}

function setFrameOptions(res) {
	res.setHeader('X-Frame-Options', 'SAMEORIGIN')
	res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
}

module.exports = function (passport) {
	router.get('/', authHandler.isAuthenticated, function (req, res) {
		setFrameOptions(res)
		res.redirect('/learn')
	})

	router.get('/login', authHandler.isNotAuthenticated, function (req, res) {
		setFrameOptions(res)
		res.render('login')
	})

	router.get('/learn/vulnerability/:vuln', authHandler.isAuthenticated, function (req, res) {
		setFrameOptions(res)
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
		setFrameOptions(res)
		res.render('learn', { vulnerabilities: vulnDict })
	})

	router.get('/register', authHandler.isNotAuthenticated, function (req, res) {
		setFrameOptions(res)
		res.render('register')
	})

	router.get('/logout', function (req, res) {
		setFrameOptions(res)
		var logoutAndRedirect = function () {
			clearSessionCookie(req, res)
			res.redirect('/')
		}

		if (typeof req.logout === 'function' && req.logout.length > 0) {
			req.logout(function (err) {
				if (err) {
					return res.redirect('/')
				}

				if (req.session && typeof req.session.destroy === 'function') {
					req.session.destroy(logoutAndRedirect)
				} else {
					logoutAndRedirect()
				}
			})
			return
		}

		if (typeof req.logout === 'function') {
			req.logout()
		}

		if (req.session && typeof req.session.destroy === 'function') {
			req.session.destroy(logoutAndRedirect)
		} else {
			logoutAndRedirect()
		}
	})

	router.get('/forgotpw', function (req, res) {
		setFrameOptions(res)
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

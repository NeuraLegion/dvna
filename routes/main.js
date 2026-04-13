var router = require('express').Router()
var vulnDict = require('../config/vulns')
var authHandler = require('../core/authHandler')
var serverConfig = require('../config/server')

function getAllowedOrigins() {
	return (serverConfig.corsOrigin || '')
		.split(',')
		.map(function (origin) {
			return origin.trim()
		})
		.filter(function (origin) {
			return origin.length > 0
		})
}

function isAllowedOrigin(requestOrigin) {
	if (!requestOrigin) {
		return false
	}

	return getAllowedOrigins().indexOf(requestOrigin) !== -1
}

module.exports = function (passport) {
	router.use(function (req, res, next) {
		res.setHeader('X-Frame-Options', 'SAMEORIGIN')
		res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
		res.setHeader('X-Content-Type-Options', 'nosniff')
		res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' https://maxcdn.bootstrapcdn.com https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://maxcdn.bootstrapcdn.com; img-src 'self' data:; font-src 'self' https://maxcdn.bootstrapcdn.com")

		var requestOrigin = req.headers.origin
		if (isAllowedOrigin(requestOrigin)) {
			res.setHeader('Vary', 'Origin')
			res.setHeader('Access-Control-Allow-Origin', requestOrigin)
			res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
			res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization')
		}

		if (req.method === 'OPTIONS') {
			return res.sendStatus(204)
		}

		next()
	})

	router.get('/', authHandler.isAuthenticated, function (req, res) {
		res.redirect('/learn')
	})

	router.get('/login', authHandler.isNotAuthenticated, function (req, res) {
		res.render('login')
	})

	router.get('/learn/vulnerability/:vuln', authHandler.isAuthenticated, function (req, res) {
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
		res.render('learn', { vulnerabilities: vulnDict })
	})

	router.get('/register', authHandler.isNotAuthenticated, function (req, res) {
		res.render('register')
	})

	router.get('/logout', function (req, res) {
		if (req.logout) {
			req.logout()
		}

		if (req.session) {
			req.session.destroy(function () {
				res.clearCookie('connect.sid', {
					httpOnly: true,
					secure: true,
					sameSite: 'lax'
				})
				res.redirect('/')
			})
			return
		}

		res.clearCookie('connect.sid', {
			httpOnly: true,
			secure: true,
			sameSite: 'lax'
		})
		res.redirect('/')
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
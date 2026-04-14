var router = require('express').Router()
var vulnDict = require('../config/vulns')
var authHandler = require('../core/authHandler')

var allowedOrigins = (process.env.CORS_ORIGINS || '').split(',').map(function (origin) {
	return origin.trim()
}).filter(Boolean)

function setCorsHeaders(req, res) {
	var requestOrigin = req.headers.origin

	if (requestOrigin && allowedOrigins.indexOf(requestOrigin) !== -1) {
		res.setHeader('Access-Control-Allow-Origin', requestOrigin)
		res.setHeader('Vary', 'Origin')
		return true
	}

	return false
}

function setSecurityHeaders(req, res) {
	if (!res.getHeader('X-Frame-Options')) {
		res.setHeader('X-Frame-Options', 'SAMEORIGIN')
	}

	if (!res.getHeader('Strict-Transport-Security') && (req.secure || req.headers['x-forwarded-proto'] === 'https')) {
		res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
	}
}

function clearSessionCookie(req, res) {
	var isSecureRequest = req.secure || req.headers['x-forwarded-proto'] === 'https'

	res.clearCookie('connect.sid', {
		path: '/',
		httpOnly: true,
		secure: isSecureRequest,
		sameSite: 'lax'
	})
}

module.exports = function (passport) {
	router.use(function (req, res, next) {
		setSecurityHeaders(req, res)
		next()
	})

	router.get('/', authHandler.isAuthenticated, function (req, res) {
		res.redirect('/learn')
	})

	router.get('/login', authHandler.isNotAuthenticated, function (req, res) {
		res.render('login')
	})

	router.get('/learn/vulnerability/:vuln', authHandler.isAuthenticated, function (req, res) {
		setCorsHeaders(req, res)
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
		setCorsHeaders(req, res)
		res.render('learn', { vulnerabilities: vulnDict })
	})

	router.get('/register', authHandler.isNotAuthenticated, function (req, res) {
		res.render('register')
	})

	router.get('/logout', function (req, res) {
		req.logout(function (err) {
			if (err) {
				return res.redirect('/')
			}

			if (req.session) {
				req.session.destroy(function () {
					clearSessionCookie(req, res)
					res.redirect('/')
				})
			} else {
				clearSessionCookie(req, res)
				res.redirect('/')
			}
		})
	})

	router.get('/forgotpw', function (req, res) {
		setSecurityHeaders(req, res)
		setCorsHeaders(req, res)
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

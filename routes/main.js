var router = require('express').Router()
var vulnDict = require('../config/vulns')
var authHandler = require('../core/authHandler')

var allowedOrigins = (process.env.CORS_ORIGINS || '').split(',').map(function (origin) {
	return origin.trim()
}).filter(Boolean)

var cspHeaderValue = "default-src 'self'; script-src 'self' https://maxcdn.bootstrapcdn.com https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://maxcdn.bootstrapcdn.com; img-src 'self' data:; font-src 'self' https://maxcdn.bootstrapcdn.com; object-src 'none'; base-uri 'self'; frame-ancestors 'self'"

function getAllowedOrigin(req) {
	var requestOrigin = req && req.headers ? req.headers.origin : null

	if (requestOrigin && allowedOrigins.indexOf(requestOrigin) !== -1) {
		return requestOrigin
	}

	return null
}

function setCorsHeaders(req, res) {
	var allowedOrigin = getAllowedOrigin(req)

	if (!allowedOrigin) {
		return false
	}

	res.setHeader('Access-Control-Allow-Origin', allowedOrigin)

	var vary = res.getHeader('Vary')
	if (!vary) {
		res.setHeader('Vary', 'Origin')
	} else if (String(vary).indexOf('Origin') === -1) {
		res.setHeader('Vary', String(vary) + ', Origin')
	}

	return true
}

function shouldUseSecureCookie(req) {
	if (process.env.NODE_ENV === 'production' || process.env.HTTPS === 'true') {
		return true
	}

	return Boolean(req && (req.secure || (req.headers && req.headers['x-forwarded-proto'] === 'https')))
}

function clearSessionCookie(req, res) {
	res.clearCookie('connect.sid', {
		path: '/',
		httpOnly: true,
		secure: shouldUseSecureCookie(req),
		sameSite: 'lax'
	})
}

function setSecurityHeaders(req, res) {
	setCorsHeaders(req, res)
	res.setHeader('X-Frame-Options', 'SAMEORIGIN')
	res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
	res.setHeader('Content-Security-Policy', cspHeaderValue)
	res.setHeader('X-Content-Type-Options', 'nosniff')
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

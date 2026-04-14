var router = require('express').Router()
var vulnDict = require('../config/vulns')
var authHandler = require('../core/authHandler')

var allowedOrigins = (process.env.CORS_ORIGINS || '').split(',').map(function (origin) {
	return origin.trim()
}).filter(Boolean)

var contentSecurityPolicy = "default-src 'self'; script-src 'self' https://maxcdn.bootstrapcdn.com https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://maxcdn.bootstrapcdn.com; img-src 'self' data:; font-src 'self' https://maxcdn.bootstrapcdn.com; object-src 'none'; base-uri 'self'; frame-ancestors 'self'"

function setCorsHeaders(req, res) {
	var requestOrigin = req.headers.origin

	if (requestOrigin && allowedOrigins.indexOf(requestOrigin) !== -1) {
		if (!res.getHeader('Access-Control-Allow-Origin')) {
			res.setHeader('Access-Control-Allow-Origin', requestOrigin)
		}

		if (!res.getHeader('Vary')) {
			res.setHeader('Vary', 'Origin')
		} else if (String(res.getHeader('Vary')).indexOf('Origin') === -1) {
			res.setHeader('Vary', String(res.getHeader('Vary')) + ', Origin')
		}

		return true
	}

	return false
}

function setSecurityHeaders(req, res) {
	if (!res.getHeader('X-Frame-Options')) {
		res.setHeader('X-Frame-Options', 'SAMEORIGIN')
	}

	if (!res.getHeader('Content-Security-Policy')) {
		res.setHeader('Content-Security-Policy', contentSecurityPolicy)
	}

	// Ensure the MIME-sniffing protection header is always present on HTML responses.
	if (!res.getHeader('X-Content-Type-Options')) {
		res.setHeader('X-Content-Type-Options', 'nosniff')
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
	// Apply CORS consistently before route handlers so the header is present
	// whenever the request origin is allowed, including on /forgotpw.
	router.use(function (req, res, next) {
		setCorsHeaders(req, res)
		next()
	})

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

var router = require('express').Router()
var vulnDict = require('../config/vulns')
var authHandler = require('../core/authHandler')
var config = require('../config/server')

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
	var clearOptions = {
		httpOnly: true,
		sameSite: 'lax',
		secure: config.cookieSecure === true,
		path: '/'
	}

	function clearSessionCookie () {
		res.clearCookie('connect.sid', clearOptions)
		res.redirect('/')
	}

	if (req.logout) {
		try {
			req.logout()
		} catch (e) {}
	}

	if (req.session) {
		req.session.destroy(function () {
			clearSessionCookie()
		})
		return
	}

	clearSessionCookie()
})

router.get('/forgotpw', function (req, res) {
	res.render('forgotpw')
})

router.get('/resetpw', authHandler.resetPw)

router.post('/login', authHandler.isNotAuthenticated, function (req, res, next) {
	authHandler.login && authHandler.login(req, res, next)
})

router.post('/register', authHandler.isNotAuthenticated, function (req, res, next) {
	authHandler.register && authHandler.register(req, res, next)
})

router.post('/forgotpw', authHandler.forgotPw)

router.post('/resetpw', authHandler.resetPwSubmit)

module.exports = function (passport) {
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

	return router
}
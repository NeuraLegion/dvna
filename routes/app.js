var router = require('express').Router()
var appHandler = require('../core/appHandler')
var authHandler = require('../core/authHandler')
var serverConfig = require('../config/server')

function isSecureRequest(req) {
	return req.secure || req.headers['x-forwarded-proto'] === 'https'
}

function getAllowedOrigins() {
	var configured = serverConfig.corsOrigin || ''

	return configured.split(',').map(function (origin) {
		return origin.trim()
	}).filter(function (origin) {
		return origin.length > 0
	})
}

function setCorsHeaders(req, res) {
	var requestOrigin = req.headers.origin
	var allowedOrigins = getAllowedOrigins()

	if (!requestOrigin || allowedOrigins.length === 0) {
		return
	}

	if (allowedOrigins.indexOf(requestOrigin) !== -1) {
		res.setHeader('Access-Control-Allow-Origin', requestOrigin)
		res.setHeader('Vary', 'Origin')
	}
}

function setSecurityHeaders(req, res, next) {
	res.setHeader('X-Frame-Options', 'SAMEORIGIN')
	res.setHeader('X-Content-Type-Options', 'nosniff')
	setCorsHeaders(req, res)

	if (isSecureRequest(req)) {
		res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
	}

	var csp = "default-src 'self'; script-src 'self' https://maxcdn.bootstrapcdn.com https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://maxcdn.bootstrapcdn.com https://cdnjs.cloudflare.com; img-src 'self' data:; font-src 'self' https://maxcdn.bootstrapcdn.com https://cdnjs.cloudflare.com data:; object-src 'none'; base-uri 'self'; frame-ancestors 'self'"
	if (!res.getHeader('Content-Security-Policy')) {
		res.setHeader('Content-Security-Policy', csp)
	}
	return next()
}

function isAllowedRedirectTarget(url) {
	if (typeof url !== 'string') {
		return false
	}

	url = url.trim()
	if (!url) {
		return false
	}

	// Allow only same-site relative paths and explicitly approved destinations.
	// This blocks protocol-relative URLs, absolute external URLs, and javascript/data schemes.
	var allowedTargets = [
		'/learn',
		'/app/learn',
		'/app/products',
		'/app/usersearch',
		'/app/ping',
		'/app/calc',
		'/app/admin',
		'/app/useredit',
		'/app/bulkproducts'
	]

	if (allowedTargets.indexOf(url) !== -1) {
		return true
	}

	return /^\/(?!\/)[A-Za-z0-9/_\-?=&%.]*$/.test(url)
}

module.exports = function () {
	router.use(setSecurityHeaders)

	router.get('/', authHandler.isAuthenticated, function (req, res) {
		res.redirect('/learn')
	})

	router.get('/usersearch', authHandler.isAuthenticated, function (req, res) {
		res.render('app/usersearch', {
			output: null
		})
	})

	router.get('/ping', authHandler.isAuthenticated, function (req, res) {
		res.render('app/ping', {
			output: null
		})
	})

	router.get('/bulkproducts', authHandler.isAuthenticated, function (req, res) {
		res.render('app/bulkproducts', {legacy: req.query.legacy})
	})

	router.get('/products', authHandler.isAuthenticated, function (req, res) {
		appHandler.listProducts(req, res)
	})

	router.get('/modifyproduct', authHandler.isAuthenticated, function (req, res) {
		appHandler.modifyProduct(req, res)
	})

	router.get('/useredit', authHandler.isAuthenticated, function (req, res) {
		appHandler.userEdit(req, res)
	})

	router.get('/calc', authHandler.isAuthenticated, function (req, res) {
		res.render('app/calc', {output: null})
	})

	router.get('/admin', authHandler.isAuthenticated, function (req, res) {
		res.render('app/admin', {
			admin: (req.user.role == 'admin')
		})
	})

	router.get('/admin/usersapi', authHandler.isAuthenticated, function (req, res) {
		appHandler.listUsersAPI(req, res)
	})

	router.get('/admin/users', authHandler.isAuthenticated, function(req, res){
		res.render('app/adminusers')
	})

	router.get('/redirect', authHandler.isAuthenticated, function (req, res) {
		var target = req.query.url

		if (!isAllowedRedirectTarget(target)) {
			return res.status(400).send('invalid redirect url')
		}

		return res.redirect(target)
	})

	router.post('/usersearch', authHandler.isAuthenticated, function (req, res) {
		appHandler.userSearch(req, res)
	})

	router.post('/ping', authHandler.isAuthenticated, function (req, res) {
		appHandler.ping(req, res)
	})

	router.post('/products', authHandler.isAuthenticated, function (req, res) {
		appHandler.productSearch(req, res)
	})

	router.post('/modifyproduct', authHandler.isAuthenticated, function (req, res) {
		appHandler.modifyProductSubmit(req, res)
	})

	router.post('/useredit', authHandler.isAuthenticated, function (req, res) {
		appHandler.userEditSubmit(req, res)
	})

	router.post('/calc', authHandler.isAuthenticated, function (req, res) {
		appHandler.calc(req, res)
	})

	router.post('/bulkproducts', authHandler.isAuthenticated, function(req, res) {
		appHandler.bulkProducts(req, res)
	})

	router.post('/bulkproductslegacy', authHandler.isAuthenticated, function(req, res) {
		appHandler.bulkProductsLegacy(req, res)
	})

	return router
}

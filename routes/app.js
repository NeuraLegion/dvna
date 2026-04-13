var router = require('express').Router()
var appHandler = require('../core/appHandler')
var authHandler = require('../core/authHandler')

function setSecurityHeaders(req, res, next) {
	res.setHeader('X-Frame-Options', 'SAMEORIGIN')
	res.setHeader('X-Content-Type-Options', 'nosniff')
	res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
	res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' https://maxcdn.bootstrapcdn.com https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://maxcdn.bootstrapcdn.com; img-src 'self' data:; font-src 'self' https://maxcdn.bootstrapcdn.com data:; object-src 'none'; base-uri 'self'; frame-ancestors 'self'")
	return next()
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
		return appHandler.redirect(req, res)
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

var router = require('express').Router()
var appHandler = require('../core/appHandler')
var authHandler = require('../core/authHandler')
var serverConfig = require('../config/server')

function setCorsHeaders(req, res) {
    var origin = req.get('Origin')

    if (!origin) {
        return
    }

    if (serverConfig.corsOrigin && origin === serverConfig.corsOrigin) {
        res.setHeader('Access-Control-Allow-Origin', origin)
        res.setHeader('Vary', 'Origin')
        res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization')
    }
}

function setFrameProtectionHeaders(res) {
    res.setHeader('X-Frame-Options', 'SAMEORIGIN')
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
    res.setHeader('Content-Security-Policy', "default-src 'self'; frame-ancestors 'self'")
    res.setHeader('X-Content-Type-Options', 'nosniff')
}

module.exports = function () {
    router.use(function (req, res, next) {
        setFrameProtectionHeaders(res)
        next()
    })

    router.get('/', authHandler.isAuthenticated, function (req, res) {
        res.redirect('/learn')
    })

    router.get('/usersearch', authHandler.isAuthenticated, function (req, res) {
        setCorsHeaders(req, res)
        setFrameProtectionHeaders(res)
        res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' https://maxcdn.bootstrapcdn.com https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://maxcdn.bootstrapcdn.com; img-src 'self' data:; font-src 'self' https://maxcdn.bootstrapcdn.com data:; object-src 'none'; base-uri 'self'; frame-ancestors 'self'")
        res.render('app/usersearch', {
            output: null
        })
    })

    router.get('/ping', authHandler.isAuthenticated, function (req, res) {
        setFrameProtectionHeaders(res)
        res.render('app/ping', {
            output: null
        })
    })

    router.get('/bulkproducts', authHandler.isAuthenticated, function (req, res) {
        setCorsHeaders(req, res)
        setFrameProtectionHeaders(res)
        res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' https://maxcdn.bootstrapcdn.com https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://maxcdn.bootstrapcdn.com; img-src 'self' data:; font-src 'self' https://maxcdn.bootstrapcdn.com data:; object-src 'none'; base-uri 'self'; frame-ancestors 'self'")
        res.render('app/bulkproducts',{legacy:req.query.legacy})
    })

    router.get('/products', authHandler.isAuthenticated, appHandler.listProducts)

    router.get('/modifyproduct', authHandler.isAuthenticated, function (req, res) {
        setCorsHeaders(req, res)
        res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
        res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' https://maxcdn.bootstrapcdn.com https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://maxcdn.bootstrapcdn.com; img-src 'self' data:; font-src 'self' https://maxcdn.bootstrapcdn.com data:; object-src 'none'; base-uri 'self'; frame-ancestors 'self'")
        res.setHeader('X-Content-Type-Options', 'nosniff')
        appHandler.modifyProduct(req, res)
    })

    router.get('/useredit', authHandler.isAuthenticated, appHandler.userEdit)

    router.get('/calc', authHandler.isAuthenticated, function (req, res) {
        setCorsHeaders(req, res)
        setFrameProtectionHeaders(res)
        res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' https://maxcdn.bootstrapcdn.com https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://maxcdn.bootstrapcdn.com; img-src 'self' data:; font-src 'self' https://maxcdn.bootstrapcdn.com data:; object-src 'none'; base-uri 'self'; frame-ancestors 'self'")
        res.render('app/calc',{output:null})
    })

    router.get('/admin', authHandler.isAuthenticated, function (req, res) {
        res.render('app/admin', {
            admin: (req.user.role == 'admin')
        })
    })

    router.get('/admin/usersapi', authHandler.isAuthenticated, appHandler.listUsersAPI)

    router.get('/admin/users', authHandler.isAuthenticated, function(req, res){
        res.render('app/adminusers')
    })

    router.get('/redirect', appHandler.redirect)

    router.post('/usersearch', authHandler.isAuthenticated, appHandler.userSearch)

    router.post('/ping', authHandler.isAuthenticated, function (req, res) {
        setFrameProtectionHeaders(res)
        appHandler.ping(req, res)
    })

    router.options('/products', authHandler.isAuthenticated, function (req, res) {
        setCorsHeaders(req, res)
        res.sendStatus(204)
    })

    router.post('/products', authHandler.isAuthenticated, function (req, res) {
        setCorsHeaders(req, res)
        setFrameProtectionHeaders(res)
        res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'")
        appHandler.productSearch(req, res)
    })

    router.post('/modifyproduct', authHandler.isAuthenticated, appHandler.modifyProductSubmit)

    router.post('/useredit', authHandler.isAuthenticated, appHandler.userEditSubmit)

    router.post('/calc', authHandler.isAuthenticated, appHandler.calc)

    router.post('/bulkproducts',authHandler.isAuthenticated, appHandler.bulkProducts);

    router.post('/bulkproductslegacy',authHandler.isAuthenticated, appHandler.bulkProductsLegacy);

    return router
}

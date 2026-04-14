var router = require('express').Router()
var appHandler = require('../core/appHandler')
var authHandler = require('../core/authHandler')

var allowedOrigins = (process.env.CORS_ORIGINS || '').split(',').map(function (origin) {
    return origin.trim()
}).filter(Boolean)

function setCorsHeaders(req, res) {
    var requestOrigin = req.headers.origin

    if (requestOrigin && allowedOrigins.indexOf(requestOrigin) !== -1) {
        res.setHeader('Access-Control-Allow-Origin', requestOrigin)
        res.setHeader('Vary', 'Origin')
        res.setHeader('Access-Control-Allow-Credentials', 'true')
        res.setHeader('Access-Control-Allow-Methods', 'GET,POST')
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With')
        return true
    }

    return false
}

function setSecurityHeaders(req, res, next) {
    var csp = "default-src 'self'; script-src 'self' https://maxcdn.bootstrapcdn.com https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://maxcdn.bootstrapcdn.com; img-src 'self' data:; font-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'self'"

    // Set headers on every /app response path, including rendered pages like /app/calc.
    res.setHeader('X-Frame-Options', 'SAMEORIGIN')
    res.setHeader('Content-Security-Policy', csp)
    res.setHeader('X-Content-Type-Options', 'nosniff')

    // Preserve HSTS if it is not already present.
    if (!res.getHeader('Strict-Transport-Security')) {
        res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
    }

    next()
}

function applySecurityHeaders(req, res, next) {
    setSecurityHeaders(req, res, next)
}

module.exports = function (app) {
    if (app && typeof app.set === 'function') {
        app.set('trust proxy', 1)
    }

    // Apply security headers before any route handlers so all responses inherit them.
    router.use(applySecurityHeaders)

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
        res.render('app/bulkproducts',{legacy:req.query.legacy})
    })

    router.get('/products', authHandler.isAuthenticated, function (req, res, next) {
        setCorsHeaders(req, res)
        next()
    }, appHandler.listProducts)

    router.get('/modifyproduct', authHandler.isAuthenticated, appHandler.modifyProduct)

    router.get('/useredit', authHandler.isAuthenticated, appHandler.userEdit)

    router.get('/calc', authHandler.isAuthenticated, function (req, res) {
        // Re-assert the CSP on the rendered response to cover any downstream middleware
        // or response handling that could otherwise omit headers.
        setSecurityHeaders(req, res, function () {})
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

    router.post('/usersearch', authHandler.isAuthenticated, function (req, res, next) {
        setCorsHeaders(req, res)
        next()
    }, appHandler.userSearch)

    router.post('/ping', authHandler.isAuthenticated, function (req, res, next) {
        setCorsHeaders(req, res)
        next()
    }, appHandler.ping)

    router.post('/products', authHandler.isAuthenticated, appHandler.productSearch)

    router.post('/modifyproduct', authHandler.isAuthenticated, function (req, res, next) {
        setCorsHeaders(req, res)
        next()
    }, appHandler.modifyProductSubmit)

    router.post('/useredit', authHandler.isAuthenticated, appHandler.userEditSubmit)

    router.post('/calc', authHandler.isAuthenticated, function (req, res, next) {
        setCorsHeaders(req, res)
        next()
    }, appHandler.calc)

    router.post('/bulkproducts',authHandler.isAuthenticated, appHandler.bulkProducts)

    router.post('/bulkproductslegacy',authHandler.isAuthenticated, appHandler.bulkProductsLegacy)

    return router
}

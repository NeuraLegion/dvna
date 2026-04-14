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
        res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
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

    if (typeof next === 'function') {
        next()
    }
}

function applySecurityHeaders(req, res, next) {
    setSecurityHeaders(req, res, next)
}

module.exports = function (app) {
    if (app && typeof app.set === 'function') {
        app.set('trust proxy', 1)
    }

    // Apply security headers before any route handlers so all responses inherit them.
    // Also make sure the header is set again on the finished response in case any
    // downstream middleware or route handler short-circuits the request path.
    router.use(function (req, res, next) {
        setSecurityHeaders(req, res, function () {})
        next()
    })

    router.use(applySecurityHeaders)

    router.use(function (req, res, next) {
        res.setHeader('X-Content-Type-Options', 'nosniff')
        next()
    })

    router.options('/calc', authHandler.isAuthenticated, function (req, res) {
        setCorsHeaders(req, res)
        res.setHeader('X-Content-Type-Options', 'nosniff')
        res.sendStatus(204)
    })

    router.get('/', authHandler.isAuthenticated, function (req, res) {
        res.setHeader('X-Content-Type-Options', 'nosniff')
        res.redirect('/learn')
    })

    router.get('/usersearch', authHandler.isAuthenticated, function (req, res) {
        res.setHeader('X-Content-Type-Options', 'nosniff')
        res.render('app/usersearch', {
            output: null
        })
    })

    router.get('/ping', authHandler.isAuthenticated, function (req, res) {
        res.setHeader('X-Content-Type-Options', 'nosniff')
        res.render('app/ping', {
            output: null
        })
    })

    router.get('/bulkproducts', authHandler.isAuthenticated, function (req, res) {
        res.setHeader('X-Content-Type-Options', 'nosniff')
        res.render('app/bulkproducts',{legacy:req.query.legacy})
    })

    router.get('/products', authHandler.isAuthenticated, function (req, res, next) {
        setCorsHeaders(req, res)
        res.setHeader('X-Content-Type-Options', 'nosniff')
        next()
    }, appHandler.listProducts)

    router.get('/modifyproduct', authHandler.isAuthenticated, appHandler.modifyProduct)

    router.get('/useredit', authHandler.isAuthenticated, appHandler.userEdit)

    router.get('/calc', authHandler.isAuthenticated, function (req, res) {
        // Ensure CORS is applied on the rendered GET page when the request comes
        // from a trusted origin, matching the POST /calc behavior.
        setCorsHeaders(req, res)

        // Re-assert the security headers immediately before rendering to ensure
        // the response always carries nosniff even if another middleware altered them.
        setSecurityHeaders(req, res, function () {})
        res.setHeader('X-Content-Type-Options', 'nosniff')
        res.render('app/calc',{output:null})
    })

    router.get('/admin', authHandler.isAuthenticated, function (req, res) {
        res.setHeader('X-Content-Type-Options', 'nosniff')
        res.render('app/admin', {
            admin: (req.user.role == 'admin')
        })
    })

    router.get('/admin/usersapi', authHandler.isAuthenticated, appHandler.listUsersAPI)

    router.get('/admin/users', authHandler.isAuthenticated, function(req, res){
        res.setHeader('X-Content-Type-Options', 'nosniff')
        res.render('app/adminusers')
    })

    router.get('/redirect', appHandler.redirect)

    router.post('/usersearch', authHandler.isAuthenticated, function (req, res, next) {
        setCorsHeaders(req, res)
        res.setHeader('X-Content-Type-Options', 'nosniff')
        next()
    }, appHandler.userSearch)

    router.post('/ping', authHandler.isAuthenticated, function (req, res, next) {
        setCorsHeaders(req, res)
        res.setHeader('X-Content-Type-Options', 'nosniff')
        next()
    }, appHandler.ping)

    router.post('/products', authHandler.isAuthenticated, appHandler.productSearch)

    router.post('/modifyproduct', authHandler.isAuthenticated, function (req, res, next) {
        setCorsHeaders(req, res)
        res.setHeader('X-Content-Type-Options', 'nosniff')
        next()
    }, appHandler.modifyProductSubmit)

    router.post('/useredit', authHandler.isAuthenticated, appHandler.userEditSubmit)

    router.post('/calc', authHandler.isAuthenticated, function (req, res, next) {
        // Explicitly set the clickjacking protection on the vulnerable POST path.
        // This is defensive even though the router-level middleware should already apply it.
        setSecurityHeaders(req, res, function () {})
        setCorsHeaders(req, res)
        res.setHeader('X-Content-Type-Options', 'nosniff')
        next()
    }, appHandler.calc)

    router.post('/bulkproducts',authHandler.isAuthenticated, appHandler.bulkProducts)

    router.post('/bulkproductslegacy',authHandler.isAuthenticated, appHandler.bulkProductsLegacy)

    return router
}

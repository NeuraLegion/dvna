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

function isHttpsRequest(req) {
    if (req.secure) {
        return true
    }

    var forwardedProto = req.headers['x-forwarded-proto']
    if (typeof forwardedProto === 'string' && forwardedProto.split(',')[0].trim().toLowerCase() === 'https') {
        return true
    }

    return false
}

function setSecurityHeaders(req, res, next) {
    // Keep CSP strict enough to mitigate XSS while allowing the app's existing
    // Bootstrap/CDN dependencies and inline styles used by legacy templates.
    var csp = [
        "default-src 'self'",
        "script-src 'self' https://maxcdn.bootstrapcdn.com https://cdnjs.cloudflare.com",
        "style-src 'self' 'unsafe-inline' https://maxcdn.bootstrapcdn.com",
        "img-src 'self' data:",
        "font-src 'self' data: https://maxcdn.bootstrapcdn.com",
        "object-src 'none'",
        "base-uri 'self'",
        "frame-ancestors 'self'"
    ].join('; ')

    // Apply security headers for every /app response, including rendered pages
    // and handler-generated responses such as /app/calc.
    res.setHeader('X-Frame-Options', 'SAMEORIGIN')
    res.setHeader('Content-Security-Policy', csp)
    res.setHeader('X-Content-Type-Options', 'nosniff')

    // Emit HSTS only when the request is actually HTTPS.
    if (isHttpsRequest(req)) {
        res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
    }

    if (typeof next === 'function') {
        next()
    }
}

module.exports = function (app) {
    if (app && typeof app.set === 'function') {
        app.set('trust proxy', 1)
    }

    // Apply security headers before any route handlers so all responses inherit them.
    router.use(function (req, res, next) {
        setSecurityHeaders(req, res, next)
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
        setCorsHeaders(req, res)
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

    // Do not rely on a pre-handler callback for response security headers here.
    // The shared router.use() middleware above ensures /app/calc always gets
    // X-Content-Type-Options: nosniff, even if the handler response path changes.
    router.post('/calc', authHandler.isAuthenticated, function (req, res) {
        setCorsHeaders(req, res)
        appHandler.calc(req, res)
    })

    router.post('/bulkproducts',authHandler.isAuthenticated, appHandler.bulkProducts)

    router.post('/bulkproductslegacy',authHandler.isAuthenticated, appHandler.bulkProductsLegacy)

    return router
}

var router = require('express').Router()
var appHandler = require('../core/appHandler')
var authHandler = require('../core/authHandler')

var allowedOrigins = (process.env.CORS_ORIGINS || '').split(',').map(function (origin) {
    return origin.trim()
}).filter(Boolean)

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

    res.setHeader('Access-Control-Allow-Credentials', 'true')
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With')

    return true
}

function setSecurityHeaders(req, res, next) {
    // Apply response security headers early for every /app request path so they
    // are present on rendered pages, redirects, and POST responses such as
    // /app/usersearch.
    if (!res.getHeader('X-Frame-Options')) {
        res.setHeader('X-Frame-Options', 'SAMEORIGIN')
    }

    if (!res.getHeader('X-Content-Type-Options')) {
        res.setHeader('X-Content-Type-Options', 'nosniff')
    }

    if (!res.getHeader('Content-Security-Policy')) {
        res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' https://maxcdn.bootstrapcdn.com https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://maxcdn.bootstrapcdn.com; img-src 'self' data:; font-src 'self' data: https://maxcdn.bootstrapcdn.com; object-src 'none'; base-uri 'self'; frame-ancestors 'self'; form-action 'self'")
    }

    if ((req.secure || req.headers['x-forwarded-proto'] === 'https') && !res.getHeader('Strict-Transport-Security')) {
        res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
    }

    next()
}

function corsAndSecurityMiddleware(req, res, next) {
    setCorsHeaders(req, res)
    setSecurityHeaders(req, res, next)
}

module.exports = function (app) {
    if (app && typeof app.set === 'function') {
        app.set('trust proxy', 1)
        app.set('env', process.env.NODE_ENV || 'development')
    }

    // Ensure the header is set for all /app routes before any handler can end
    // the response.
    router.use(corsAndSecurityMiddleware)

    router.options('*', function (req, res) {
        if (setCorsHeaders(req, res)) {
            return res.sendStatus(204)
        }

        return res.sendStatus(405)
    })

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

    router.get('/products', authHandler.isAuthenticated, appHandler.listProducts)

    router.get('/modifyproduct', authHandler.isAuthenticated, appHandler.modifyProduct)

    router.get('/useredit', authHandler.isAuthenticated, appHandler.userEdit)

    router.get('/calc', authHandler.isAuthenticated, function (req, res) {
        res.render('app/calc', {output: null})
    })

    router.get('/admin', authHandler.isAuthenticated, function (req, res) {
        res.render('app/admin', {
            admin: (req.user.role == 'admin')
        })
    })

    router.get('/admin/usersapi', authHandler.isAuthenticated, appHandler.listUsersAPI)

    router.get('/admin/users', authHandler.isAuthenticated, function (req, res) {
        res.render('app/adminusers')
    })

    router.get('/redirect', appHandler.redirect)

    // POST /app/usersearch is the DAST-identified path; the middleware above
    // guarantees the CSP header is emitted even for handler-rendered responses.
    router.post('/usersearch', authHandler.isAuthenticated, appHandler.userSearch)

    router.post('/ping', authHandler.isAuthenticated, appHandler.ping)

    router.post('/products', authHandler.isAuthenticated, appHandler.productSearch)

    router.post('/modifyproduct', authHandler.isAuthenticated, appHandler.modifyProductSubmit)

    router.post('/useredit', authHandler.isAuthenticated, appHandler.userEditSubmit)

    router.post('/calc', authHandler.isAuthenticated, appHandler.calc)

    router.post('/bulkproducts', authHandler.isAuthenticated, appHandler.bulkProducts)

    router.post('/bulkproductslegacy', authHandler.isAuthenticated, appHandler.bulkProductsLegacy)

    return router
}

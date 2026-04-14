var router = require('express').Router()
var appHandler = require('../core/appHandler')
var authHandler = require('../core/authHandler')

var allowedOrigins = (process.env.CORS_ORIGINS || '').split(',').map(function (origin) {
    return origin.trim()
}).filter(Boolean)

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

        if (!res.getHeader('Access-Control-Allow-Credentials')) {
            res.setHeader('Access-Control-Allow-Credentials', 'true')
        }

        if (!res.getHeader('Access-Control-Allow-Methods')) {
            res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
        }

        if (!res.getHeader('Access-Control-Allow-Headers')) {
            res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With')
        }

        return true
    }

    return false
}

function setSecurityHeaders(req, res, next) {
    // Enforce clickjacking protection on all /app routes.
    if (!res.getHeader('X-Frame-Options')) {
        res.setHeader('X-Frame-Options', 'SAMEORIGIN')
    }

    if (!res.getHeader('Content-Security-Policy')) {
        res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' https://maxcdn.bootstrapcdn.com https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://maxcdn.bootstrapcdn.com; img-src 'self' data:; font-src 'self' data: https://maxcdn.bootstrapcdn.com; object-src 'none'; base-uri 'self'; frame-ancestors 'self'; form-action 'self'")
    }

    if (!res.getHeader('X-Content-Type-Options')) {
        res.setHeader('X-Content-Type-Options', 'nosniff')
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

    // Attach protection before any route handler can render a response.
    router.use(corsAndSecurityMiddleware)

    router.options('/calc', authHandler.isAuthenticated, function (req, res) {
        if (setCorsHeaders(req, res)) {
            return res.sendStatus(204)
        }
        return res.sendStatus(204)
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
        setCorsHeaders(req, res)
        if (!res.getHeader('X-Content-Type-Options')) {
            res.setHeader('X-Content-Type-Options', 'nosniff')
        }
        if (!res.getHeader('X-Frame-Options')) {
            res.setHeader('X-Frame-Options', 'SAMEORIGIN')
        }
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

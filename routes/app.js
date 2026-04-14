var router = require('express').Router()
var appHandler = require('../core/appHandler')
var authHandler = require('../core/authHandler')

var allowedOrigins = [
    process.env.APP_ORIGIN
].filter(Boolean)

function setCorsHeaders(req, res, next) {
    var origin = req.headers.origin

    if (origin && allowedOrigins.indexOf(origin) !== -1) {
        res.set('Access-Control-Allow-Origin', origin)
        res.set('Vary', 'Origin')
        res.set('Access-Control-Allow-Credentials', 'true')
    }

    next()
}

function setFrameOptionsHeader(req, res, next) {
    res.set('X-Frame-Options', 'SAMEORIGIN')
    next()
}

function setHstsHeader(req, res, next) {
    var isHttps = req.secure || req.headers['x-forwarded-proto'] === 'https'

    if (isHttps) {
        res.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
    }

    next()
}

function setCspHeader(req, res, next) {
    res.set('Content-Security-Policy', "default-src 'self'; script-src 'self' https://maxcdn.bootstrapcdn.com https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://maxcdn.bootstrapcdn.com; img-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'self'")
    next()
}

function setNoSniffHeader(req, res, next) {
    res.set('X-Content-Type-Options', 'nosniff')
    next()
}

module.exports = function () {
    router.use(setCorsHeaders)
    router.use(setFrameOptionsHeader)
    router.use(setHstsHeader)
    router.use(setCspHeader)
    router.use(setNoSniffHeader)

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

    router.get('/products', authHandler.isAuthenticated, appHandler.listProducts)

    router.get('/modifyproduct', authHandler.isAuthenticated, appHandler.modifyProduct)

    router.get('/useredit', authHandler.isAuthenticated, appHandler.userEdit)

    router.get('/calc', authHandler.isAuthenticated, function (req, res) {
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

    router.post('/ping', authHandler.isAuthenticated, appHandler.ping)

    router.post('/products', authHandler.isAuthenticated, appHandler.productSearch)

    router.post('/modifyproduct', authHandler.isAuthenticated, appHandler.modifyProductSubmit)

    router.post('/useredit', authHandler.isAuthenticated, appHandler.userEditSubmit)

    router.post('/calc', authHandler.isAuthenticated, appHandler.calc)

    router.post('/bulkproducts',authHandler.isAuthenticated, appHandler.bulkProducts);

    router.post('/bulkproductslegacy',authHandler.isAuthenticated, appHandler.bulkProductsLegacy);

    return router
}

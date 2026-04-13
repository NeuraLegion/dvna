var router = require('express').Router()
var appHandler = require('../core/appHandler')
var authHandler = require('../core/authHandler')

module.exports = function () {
    var allowedOrigins = (process.env.CORS_ALLOWED_ORIGINS || '')
        .split(',')
        .map(function (origin) { return origin.trim() })
        .filter(function (origin) { return origin.length > 0 })

    function setCorsHeaders(req, res, next) {
        var origin = req.headers.origin

        if (origin && allowedOrigins.indexOf(origin) !== -1) {
            res.setHeader('Access-Control-Allow-Origin', origin)
            res.setHeader('Vary', 'Origin')
        }

        next()
    }

    function setFrameOptionsHeader(req, res, next) {
        res.setHeader('X-Frame-Options', 'SAMEORIGIN')
        next()
    }

    function setHstsHeader(req, res, next) {
        res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
        next()
    }

    router.use(setHstsHeader)
    router.use(setFrameOptionsHeader)

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

    router.get('/bulkproducts', authHandler.isAuthenticated, setCorsHeaders, function (req, res) {
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

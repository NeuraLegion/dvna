var router = require('express').Router()
var appHandler = require('../core/appHandler')
var authHandler = require('../core/authHandler')

module.exports = function () {
    router.get('/', authHandler.isAuthenticated, function (req, res) {
        res.redirect('/learn')
    })

    router.get('/usersearch', authHandler.isAuthenticated, function (req, res) {
        res.render('app/usersearch', {
            output: null,
            csrfToken: req.csrfToken()
        })
    })

    router.get('/ping', authHandler.isAuthenticated, validateOrigin, function (req, res) {
        if (Object.keys(req.query || {}).length > 0) {
            return res.status(400).send('Bad Request')
        }
        res.render('app/ping', {
            output: null,
            csrfToken: req.session.csrfFormToken
        })
    })

    router.get('/bulkproducts', authHandler.isAuthenticated, function (req, res) {
        res.render('app/bulkproducts', { legacy: false })
    })

    router.get('/products', authHandler.isAuthenticated, appHandler.listProducts)

    router.get('/modifyproduct', authHandler.isAuthenticated, validateOrigin, function (req, res, next) {
        if (!req.csrfToken || req.method !== 'GET') {
            return res.status(403).send('Forbidden')
        }
        const token = req.get('x-csrf-token') || req.query._csrf
        if (!token || token !== req.csrfToken()) {
            return res.status(403).send('Forbidden')
        }
        return appHandler.modifyProduct(req, res, next)
    })

    router.get('/useredit', authHandler.isAuthenticated, appHandler.userEdit)

    router.get('/calc', authHandler.isAuthenticated, function (req, res) {
        res.render('app/calc',{output:null})
    })

    router.get('/admin', authHandler.isAuthenticated, validateOrigin, function (req, res) {
        res.render('app/admin', {
            admin: (req.user.role == 'admin')
        })
    })

    router.get('/admin/usersapi', authHandler.isAuthenticated, validateOrigin, function (req, res, next) {
        if (!req.csrfToken || req.method !== 'GET') {
            return res.status(403).send('Forbidden')
        }
        const token = req.get('x-csrf-token') || req.query._csrf
        if (!token || token !== req.csrfToken()) {
            return res.status(403).send('Forbidden')
        }
        return appHandler.listUsersAPI(req, res, next)
    })

    router.get('/admin/users', authHandler.isAuthenticated, validateOrigin, function(req, res){
        res.render('app/adminusers')
    })

    router.get('/redirect', appHandler.redirect)

    function validateOrigin(req, res, next) {
        const origin = req.get('origin')
        const referer = req.get('referer')
        const allowedOrigin = req.protocol + '://' + req.get('host')
        if ((origin && origin !== allowedOrigin) || (referer && !referer.startsWith(allowedOrigin))) {
            return res.status(403).send('Forbidden')
        }
        next()
    }

    router.post('/usersearch', authHandler.isAuthenticated, appHandler.userSearch)

    router.post('/ping', authHandler.isAuthenticated, validateOrigin, function (req, res, next) {
        if (!req.body || !req.body._csrf || !req.session || !req.session.csrfFormToken || req.body._csrf !== req.session.csrfFormToken) {
            return res.status(403).send('Forbidden')
        }
        return next()
    }, appHandler.ping)

    router.post('/products', authHandler.isAuthenticated, validateOrigin, appHandler.productSearch)

    router.post('/modifyproduct', authHandler.isAuthenticated, validateOrigin, appHandler.modifyProductSubmit)

    router.post('/useredit', authHandler.isAuthenticated, validateOrigin, appHandler.userEditSubmit)

    router.post('/calc', authHandler.isAuthenticated, validateOrigin, appHandler.calc)

    router.post('/bulkproducts', authHandler.isAuthenticated, validateOrigin, appHandler.bulkProducts)

    router.post('/bulkproductslegacy', authHandler.isAuthenticated, validateOrigin, appHandler.bulkProductsLegacy)

    return router
}

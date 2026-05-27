var router = require('express').Router()
var appHandler = require('../core/appHandler')
var authHandler = require('../core/authHandler')

module.exports = function () {
    router.get('/', authHandler.isAuthenticated, function (req, res) {
        res.redirect('/learn')
    })

    router.get('/usersearch', authHandler.isAuthenticated, validateOrigin, function (req, res) {
        if (Object.keys(req.query || {}).length > 0) {
            return res.status(400).send('Bad Request')
        }
        if (!req.session) {
            return res.status(403).send('Forbidden')
        }
        const formToken = req.csrfToken()
        req.session.csrfFormToken = formToken
        res.render('app/usersearch', {
            output: null,
            csrfToken: formToken
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

    router.get('/bulkproducts', authHandler.isAuthenticated, validateOrigin, function (req, res) {
        if (Object.keys(req.query || {}).length > 0) {
            return res.status(400).send('Bad Request')
        }
        res.render('app/bulkproducts', {
            legacy: false,
            csrfToken: req.session.csrfFormToken,
            messages: {}
        })
    })

    router.get('/products', authHandler.isAuthenticated, validateOrigin, function (req, res, next) {
        if (!req.session || !req.session.csrfFormToken) {
            return res.status(403).send('Forbidden')
        }
        const token = req.get('x-csrf-token') || req.query._csrf
        if (!token || token !== req.session.csrfFormToken) {
            return res.status(403).send('Forbidden')
        }
        return appHandler.listProducts(req, res, next)
    })

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

    router.get('/calc', authHandler.isAuthenticated, validateOrigin, function (req, res) {
        if (Object.keys(req.query || {}).length > 0) {
            return res.status(400).send('Bad Request')
        }
        res.render('app/calc', {
            output: null,
            csrfToken: req.session.csrfFormToken
        })
    })

    router.get('/admin', authHandler.isAuthenticated, validateOrigin, function (req, res) {
        if (Object.keys(req.query || {}).length > 0) {
            return res.status(400).send('Bad Request')
        }
        if (!req.session || !req.session.csrfFormToken) {
            return res.status(403).send('Forbidden')
        }
        res.render('app/admin', {
            admin: (req.user.role == 'admin'),
            csrfToken: req.session.csrfFormToken
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

    router.post('/usersearch', authHandler.isAuthenticated, validateOrigin, function (req, res, next) {
        if (!req.body || !req.body._csrf || !req.session || !req.session.csrfFormToken || req.body._csrf !== req.session.csrfFormToken) {
            return res.status(403).send('Forbidden')
        }
        return next()
    }, appHandler.userSearch)

    router.post('/ping', authHandler.isAuthenticated, validateOrigin, function (req, res, next) {
        if (!req.body || !req.body._csrf || !req.session || !req.session.csrfFormToken || req.body._csrf !== req.session.csrfFormToken) {
            return res.status(403).send('Forbidden')
        }
        return next()
    }, appHandler.ping)

    router.post('/products', authHandler.isAuthenticated, validateOrigin, function (req, res, next) {
        if (!req.body || !req.body._csrf || !req.session || !req.session.csrfFormToken || req.body._csrf !== req.session.csrfFormToken) {
            return res.status(403).send('Forbidden')
        }
        return next()
    }, appHandler.productSearch)

    router.post('/modifyproduct', authHandler.isAuthenticated, validateOrigin, function (req, res, next) {
        if (!req.body || !req.body._csrf || !req.session || !req.session.csrfFormToken || req.body._csrf !== req.session.csrfFormToken) {
            return res.status(403).send('Forbidden')
        }
        return next()
    }, appHandler.modifyProductSubmit)

    router.post('/useredit', authHandler.isAuthenticated, validateOrigin, function (req, res, next) {
        if (!req.body || !req.body._csrf || !req.session || !req.session.csrfFormToken || req.body._csrf !== req.session.csrfFormToken) {
            return res.status(403).send('Forbidden')
        }
        return next()
    }, appHandler.userEditSubmit)

    router.post('/calc', authHandler.isAuthenticated, validateOrigin, function (req, res, next) {
        if (!req.body || !req.body._csrf || !req.session || !req.session.csrfFormToken || req.body._csrf !== req.session.csrfFormToken) {
            return res.status(403).send('Forbidden')
        }
        return next()
    }, appHandler.calc)

    router.post('/bulkproducts', authHandler.isAuthenticated, validateOrigin, function (req, res, next) {
        if (!req.body || !req.body._csrf || !req.session || !req.session.csrfFormToken || req.body._csrf !== req.session.csrfFormToken) {
            return res.status(403).send('Forbidden')
        }
        return next()
    }, appHandler.bulkProducts)

    router.post('/bulkproductslegacy', authHandler.isAuthenticated, validateOrigin, function (req, res, next) {
        if (!req.body || !req.body._csrf || !req.session || !req.session.csrfFormToken || req.body._csrf !== req.session.csrfFormToken) {
            return res.status(403).send('Forbidden')
        }
        return next()
    }, appHandler.bulkProductsLegacy)

    return router
}

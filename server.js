var express = require('express')
var session = require('express-session')

var app = express()

// If the app is deployed behind a reverse proxy / load balancer that terminates TLS,
// Express must trust the proxy so req.secure is computed correctly.
app.set('trust proxy', 1)

function isProduction() {
    return process.env.NODE_ENV === 'production'
}

function buildSessionCookieOptions(req) {
    var secureCookie = req && req.secure

    // In production we require HTTPS for session cookies. Behind a proxy, req.secure
    // is only reliable when trust proxy is enabled above.
    return {
        httpOnly: true,
        sameSite: 'lax',
        secure: isProduction() ? secureCookie : false
    }
}

app.use(function (req, res, next) {
    // Apply session middleware once at the bootstrap layer so all routes use the same
    // cookie configuration and no handler can bypass it.
    session({
        secret: process.env.SESSION_SECRET,
        resave: false,
        saveUninitialized: false,
        cookie: buildSessionCookieOptions(req)
    })(req, res, next)
})

module.exports = app

var express = require('express')
var session = require('express-session')
var app = express()

// Behind a load balancer / reverse proxy, HTTPS is often terminated upstream.
// Trust the first proxy hop so req.secure is populated correctly.
app.set('trust proxy', 1)

function isSecureRequest (req) {
    return req.secure || req.headers['x-forwarded-proto'] === 'https'
}

app.use(session({
    secret: process.env.SESSION_SECRET || 'keyboard cat',
    resave: false,
    saveUninitialized: false,
    proxy: true,
    cookie: {
        httpOnly: true,
        sameSite: 'lax',
        secure: 'auto'
    }
}))

// Ensure any session cookies created for authenticated users are forced secure
// when the request is served over HTTPS, including reverse-proxy deployments.
app.use(function (req, res, next) {
    if (req.session && req.session.cookie) {
        req.session.cookie.httpOnly = true
        req.session.cookie.sameSite = 'lax'
        req.session.cookie.secure = isSecureRequest(req)
    }
    next()
})

module.exports = app

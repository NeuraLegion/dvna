var express = require('express')
var app = express()
var session = require('express-session')

// Trust the first proxy hop so req.secure works correctly behind TLS terminators.
app.set('trust proxy', 1)

app.use(function (req, res, next) {
    // Mark the request as secure when TLS is terminated upstream and the proxy
    // forwards the original protocol. This helps express-session set Secure cookies
    // in production HTTPS deployments while avoiding breakage on local HTTP dev.
    if (req.headers['x-forwarded-proto'] === 'https') {
        req.secure = true
    }
    next()
})

app.use(session({
    secret: 'dvanonsecret',
    resave: false,
    saveUninitialized: false,
    proxy: true,
    cookie: {
        httpOnly: true,
        secure: 'auto',
        sameSite: 'lax'
    }
}))

module.exports = app

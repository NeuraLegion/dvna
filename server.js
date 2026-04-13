var express = require('express')
var session = require('express-session')
var cookieParser = require('cookie-parser')
var serverConfig = require('./config/server')

module.exports = function (app) {
    app.use(cookieParser())

    app.use(session({
        secret: process.env.SESSION_SECRET || 'change-this-secret',
        resave: false,
        saveUninitialized: false,
        proxy: true,
        cookie: {
            secure: true,
            httpOnly: true,
            sameSite: 'lax'
        }
    }))

    // If the app is deployed behind a TLS-terminating proxy, ensure Express
    // trusts the proxy so secure cookies are only sent when the original
    // request was HTTPS.
    if (app && typeof app.set === 'function') {
        app.set('trust proxy', 1)
    }

    return app
}

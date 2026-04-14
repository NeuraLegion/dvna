var express = require('express')
var session = require('express-session')

var app = express()

var isProduction = process.env.NODE_ENV === 'production'
var isSecureCookie = isProduction || process.env.SESSION_COOKIE_SECURE === 'true'

app.use(session({
    secret: 'change-this-secret',
    resave: false,
    saveUninitialized: false,
    proxy: isProduction,
    cookie: {
        secure: isSecureCookie,
        httpOnly: true,
        sameSite: 'lax'
    }
}))

module.exports = app

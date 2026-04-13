var express = require('express')
var session = require('express-session')
var passport = require('passport')
var app = express()
var serverConfig = require('./config/server')

function isSecureRequest(req) {
    if (req.secure) {
        return true
    }

    var forwardedProto = req.get('X-Forwarded-Proto')
    if (!forwardedProto) {
        return false
    }

    return forwardedProto.split(',')[0].trim().toLowerCase() === 'https'
}

function buildSessionCookieOptions(req) {
    var secureCookie = isSecureRequest(req)

    return {
        httpOnly: true,
        secure: secureCookie,
        sameSite: 'lax'
    }
}

app.set('trust proxy', 1)

app.use(function (req, res, next) {
    req.sessionCookieOptions = buildSessionCookieOptions(req)
    next()
})

app.use(session({
    secret: serverConfig.sessionSecret,
    resave: false,
    saveUninitialized: false,
    store: store,
    proxy: true,
    cookie: {
        httpOnly: true,
        secure: true,
        sameSite: 'lax'
    }
}))

app.use(function (req, res, next) {
    if (req.session && req.session.cookie && req.sessionCookieOptions) {
        req.session.cookie.secure = req.sessionCookieOptions.secure
        req.session.cookie.httpOnly = true
        req.session.cookie.sameSite = 'lax'
    }
    next()
})

app.use(passport.initialize())
app.use(passport.session())

module.exports = app

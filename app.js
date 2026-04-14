var express = require('express')
var session = require('express-session')
var passport = require('passport')
var config = require('./config/server')

var app = express()

app.set('trust proxy', 1)

function isHttpsRequest(req) {
    return req.secure || req.headers['x-forwarded-proto'] === 'https'
}

app.use(function (req, res, next) {
    var originalEnd = res.end

    res.end = function () {
        var cookieHeader = res.getHeader('Set-Cookie')
        if (cookieHeader) {
            var cookies = Array.isArray(cookieHeader) ? cookieHeader : [cookieHeader]
            cookieHeader = cookies.map(function (cookie) {
                if (typeof cookie === 'string' && cookie.indexOf('connect.sid=') !== -1 && isHttpsRequest(req) && cookie.toLowerCase().indexOf('secure') === -1) {
                    return cookie + '; Secure'
                }

                return cookie
            })
            res.setHeader('Set-Cookie', cookieHeader)
        }

        return originalEnd.apply(this, arguments)
    }

    next()
})

app.use(session({
    secret: process.env.SESSION_SECRET || 'development-session-secret',
    resave: false,
    saveUninitialized: false,
    proxy: true,
    cookie: {
        httpOnly: true,
        sameSite: 'lax',
        secure: 'auto'
    }
}))

app.use(passport.initialize())
app.use(passport.session())

module.exports = app

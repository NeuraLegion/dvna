var express = require('express')
var app = express()
var session = require('express-session')

// Enable trust proxy support when the app is deployed behind a reverse proxy
app.set('trust proxy', 1)

// Clickjacking protection for all responses
app.use(function (req, res, next) {
    res.setHeader('X-Frame-Options', 'SAMEORIGIN')
    res.setHeader('Content-Security-Policy', "frame-ancestors 'self'")
    next()
})

app.use(session({
    secret: 'keyboard cat',
    resave: true,
    saveUninitialized: true,
    cookie: {
        secure: true,
        httpOnly: true,
        sameSite: 'lax'
    }
}))

module.exports = app

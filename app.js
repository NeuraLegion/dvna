var express = require('express')
var path = require('path')
var logger = require('morgan')
var cookieParser = require('cookie-parser')
var bodyParser = require('body-parser')
var session = require('express-session')
var passport = require('passport')
var flash = require('connect-flash')

var isHttpsRequest = require('./core/isHttpsRequest')

var app = express()

app.set('trust proxy', 1)
app.set('env', process.env.NODE_ENV || 'development')

app.use(function (req, res, next) {
    if (process.env.NODE_ENV === 'production' && !isHttpsRequest(req)) {
        return res.redirect(301, 'https://' + req.headers.host + req.originalUrl)
    }
    next()
})

app.use(function (req, res, next) {
    res.setHeader('X-Frame-Options', 'SAMEORIGIN')
    res.setHeader('X-Content-Type-Options', 'nosniff')
    res.setHeader('Referrer-Policy', 'same-origin')

    if (isHttpsRequest(req)) {
        res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
    }

    next()
})

app.use(logger('dev'))
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(session({
    secret: process.env.SESSION_SECRET || 'development-secret',
    resave: false,
    saveUninitialized: false,
    proxy: true,
    cookie: {
        httpOnly: true,
        sameSite: 'lax',
        secure: process.env.NODE_ENV === 'production'
    }
}))
app.use(flash())
app.use(passport.initialize())
app.use(passport.session())

app.use('/app', require('./routes/app'))

module.exports = app

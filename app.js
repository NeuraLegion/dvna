var express = require('express')
var path = require('path')
var cookieParser = require('cookie-parser')
var bodyParser = require('body-parser')
var flash = require('connect-flash')
var session = require('express-session')
var helmet = require('helmet')

var app = express()

function setSecurityHeaders(req, res, next) {
    res.setHeader('X-Frame-Options', 'SAMEORIGIN')
    res.setHeader('X-Content-Type-Options', 'nosniff')
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' https://maxcdn.bootstrapcdn.com https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://maxcdn.bootstrapcdn.com; img-src 'self' data:; font-src 'self' data: https://maxcdn.bootstrapcdn.com; object-src 'none'; base-uri 'self'; frame-ancestors 'self'")

    if (req.secure || req.headers['x-forwarded-proto'] === 'https') {
        res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
    }

    next()
}

app.set('trust proxy', 1)
app.use(helmet({
    frameguard: { action: 'sameorigin' },
    contentSecurityPolicy: false,
    xssFilter: false,
    noSniff: false,
    hsts: false
}))
app.use(setSecurityHeaders)

app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(session({
    secret: process.env.SESSION_SECRET || 'keyboard cat',
    resave: false,
    saveUninitialized: false
}))
app.use(flash())

module.exports = app

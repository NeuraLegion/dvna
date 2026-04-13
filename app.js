var express = require('express')
var app = express()
var path = require('path')
var fs = require('fs')
var bodyParser = require('body-parser')
var methodOverride = require('method-override')
var cookieParser = require('cookie-parser')
var session = require('express-session')
var flash = require('connect-flash')
var helmet = require('helmet')

var config = require('./config/config')
var routes = require('./routes')

app.set('views', path.join(__dirname, 'views'))
app.set('view engine', 'ejs')

app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(session({
    secret: config.sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: false
    }
}))
app.use(flash())
app.use(methodOverride())

app.use(helmet({
    frameguard: { action: 'sameorigin' },
    noSniff: true,
    referrerPolicy: { policy: 'same-origin' }
}))

app.use(function (req, res, next) {
    res.setHeader('X-Frame-Options', 'SAMEORIGIN')
    res.setHeader('X-Content-Type-Options', 'nosniff')

    if (req.secure || req.headers['x-forwarded-proto'] === 'https') {
        res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
    }

    if (!res.getHeader('Content-Security-Policy')) {
        res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' https://maxcdn.bootstrapcdn.com https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://maxcdn.bootstrapcdn.com https://cdnjs.cloudflare.com; img-src 'self' data:; font-src 'self' https://maxcdn.bootstrapcdn.com https://cdnjs.cloudflare.com data:; object-src 'none'; base-uri 'self'; frame-ancestors 'self'")
    }

    next()
})

app.use('/', routes)

module.exports = app

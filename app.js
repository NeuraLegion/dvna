var express = require('express')
var path = require('path')
var favicon = require('serve-favicon')
var logger = require('morgan')
var cookieParser = require('cookie-parser')
var bodyParser = require('body-parser')
var flash = require('connect-flash')
var fileUpload = require('express-fileupload')
var session = require('express-session')
var csurf = require('csurf')
var helmet = require('helmet')

var index = require('./routes/index')
var appRoutes = require('./routes/app')
var apiRoutes = require('./routes/api')

var app = express()

// Trust reverse proxy so secure settings work correctly when deployed behind a proxy.
app.set('trust proxy', 1)

// Enforce core security headers globally before any route handlers run.
// Helmet provides a tested default security baseline; we explicitly set HSTS
// with the required policy to ensure the header is present on all responses.
app.use(helmet())
app.use(helmet.hsts({
    maxAge: 31536000,
    includeSubDomains: true,
    preload: false
}))

app.use(function (req, res, next) {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
    res.setHeader('X-Frame-Options', 'SAMEORIGIN')
    next()
})

app.use(logger('dev'))
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(fileUpload())
app.use(express.static(path.join(__dirname, 'public')))
app.use(flash())
app.use(session({
    secret: process.env.SESSION_SECRET || 'change-me-in-production',
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        sameSite: 'lax',
        secure: true
    }
}))
app.use(csurf())

app.use('/', index())
app.use('/app', appRoutes())
app.use('/api', apiRoutes())

// error handlers omitted for brevity

module.exports = app

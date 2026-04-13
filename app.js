var express = require('express')
var path = require('path')
var favicon = require('serve-favicon')
var logger = require('morgan')
var cookieParser = require('cookie-parser')
var bodyParser = require('body-parser')
var flash = require('connect-flash')
var session = require('express-session')
var fileUpload = require('express-fileupload')
var serverConfig = require('./config/server')

var index = require('./routes/index')
var appRoutes = require('./routes/app')
var authRoutes = require('./routes/auth')

var app = express()

function isAllowedOrigin(origin) {
    if (!origin || typeof origin !== 'string') {
        return false
    }

    if (!serverConfig.corsOrigin) {
        return false
    }

    return origin === serverConfig.corsOrigin
}

function setGlobalSecurityHeaders(req, res, next) {
    var origin = req.get('Origin')

    if (isAllowedOrigin(origin)) {
        res.setHeader('Access-Control-Allow-Origin', origin)
        res.setHeader('Vary', 'Origin')
        res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With')
        res.setHeader('Access-Control-Allow-Credentials', 'true')
    }

    res.setHeader('X-Frame-Options', 'SAMEORIGIN')
    res.setHeader('X-Content-Type-Options', 'nosniff')
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' https://maxcdn.bootstrapcdn.com https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://maxcdn.bootstrapcdn.com; img-src 'self' data:; font-src 'self' https://maxcdn.bootstrapcdn.com data:; object-src 'none'; base-uri 'self'; frame-ancestors 'self'")

    if (req.method === 'OPTIONS') {
        return res.sendStatus(204)
    }

    next()
}

// view engine setup
app.set('views', path.join(__dirname, 'views'))
app.set('view engine', 'ejs')

app.use(logger('dev'))
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(session({
    secret: process.env.SESSION_SECRET || 'change-me-in-production',
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: serverConfig.cookieSecure || false,
        sameSite: 'lax'
    }
}))
app.use(flash())
app.use(fileUpload())
app.use(setGlobalSecurityHeaders)

app.use('/', index)
app.use('/auth', authRoutes())
app.use('/app', appRoutes())

// error handler
app.use(function (err, req, res, next) {
    console.error(err)
    res.status(err.status || 500)
    res.render('error', {
        message: err.message,
        error: {}
    })
})

module.exports = app

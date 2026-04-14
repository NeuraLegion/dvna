var express = require('express')
var path = require('path')
var cookieParser = require('cookie-parser')
var logger = require('morgan')
var session = require('express-session')
var passport = require('passport')
var flash = require('connect-flash')

var indexRouter = require('./routes/index')
var appRouter = require('./routes/app')

var app = express()

// Ensure HSTS is set on all HTTPS responses, including when TLS is terminated
// by a reverse proxy. The header is only added when the original request was
// made over HTTPS.
app.use(function (req, res, next) {
    var isHttps = req.secure || req.headers['x-forwarded-proto'] === 'https'

    if (isHttps) {
        res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
    }

    res.setHeader('X-Frame-Options', 'SAMEORIGIN')
    res.setHeader('Content-Security-Policy', "frame-ancestors 'self'")
    next()
})

app.use(logger('dev'))
app.use(express.json())
app.use(express.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(express.static(path.join(__dirname, 'public')))

app.use(session({
    secret: 'secret',
    resave: false,
    saveUninitialized: false
}))

app.use(passport.initialize())
app.use(passport.session())
app.use(flash())

app.use('/', indexRouter)
app.use('/app', appRouter())

module.exports = app

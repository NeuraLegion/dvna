var express = require('express')
var path = require('path')
var cookieParser = require('cookie-parser')
var logger = require('morgan')
var session = require('express-session')
var passport = require('passport')
var flash = require('connect-flash')
var helmet = require('helmet')

var indexRouter = require('./routes/index')
var appRouter = require('./routes/app')

var app = express()

app.set('trust proxy', 1)
app.set('env', process.env.NODE_ENV || 'development')

app.use(helmet({
    hsts: false
}))

app.use(function (req, res, next) {
    var isHttps = req.secure || req.headers['x-forwarded-proto'] === 'https'

    if (isHttps && !res.getHeader('Strict-Transport-Security')) {
        res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
    }

    next()
})

app.use(function (req, res, next) {
    if (!res.getHeader('X-Frame-Options')) {
        res.setHeader('X-Frame-Options', 'SAMEORIGIN')
    }

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
app.use('/app', appRouter(app))

module.exports = app

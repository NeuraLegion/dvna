var express = require('express')
var path = require('path')
var favicon = require('serve-favicon')
var logger = require('morgan')
var cookieParser = require('cookie-parser')
var bodyParser = require('body-parser')
var session = require('express-session')
var passport = require('passport')
var flash = require('connect-flash')

var index = require('./routes/index')
var app = require('./routes/app')
var learn = require('./routes/learn')
var signup = require('./routes/signup')
var login = require('./routes/login')
var profile = require('./routes/profile')

var app = express()

// view engine setup
app.set('views', path.join(__dirname, 'views'))
app.set('view engine', 'ejs')

// Security headers: set globally so every response includes them
app.use(function (req, res, next) {
    res.setHeader('X-Content-Type-Options', 'nosniff')
    res.setHeader('X-Frame-Options', 'SAMEORIGIN')
    next()
})

// existing middleware
app.use(logger('dev'))
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(express.static(path.join(__dirname, 'public')))

// routes
app.use('/', index)
app.use('/app', app)
app.use('/learn', learn)
app.use('/signup', signup)
app.use('/login', login)
app.use('/profile', profile)

// Fallback security header middleware for any response paths that may bypass earlier middleware
app.use(function (req, res, next) {
    if (!res.getHeader('X-Content-Type-Options')) {
        res.setHeader('X-Content-Type-Options', 'nosniff')
    }
    if (!res.getHeader('X-Frame-Options')) {
        res.setHeader('X-Frame-Options', 'SAMEORIGIN')
    }
    next()
})

// error handlers
app.use(function (req, res, next) {
    var err = new Error('Not Found')
    err.status = 404
    next(err)
})

app.use(function (err, req, res, next) {
    res.status(err.status || 500)
    res.setHeader('X-Content-Type-Options', 'nosniff')
    res.setHeader('X-Frame-Options', 'SAMEORIGIN')
    res.render('error', {
        message: err.message,
        error: req.app.get('env') === 'development' ? err : {}
    })
})

module.exports = app

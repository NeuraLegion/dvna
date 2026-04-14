var express = require('express')
var path = require('path')
var favicon = require('serve-favicon')
var logger = require('morgan')
var cookieParser = require('cookie-parser')
var bodyParser = require('body-parser')
var session = require('express-session')
var passport = require('passport')
var flash = require('connect-flash')
var helmet = require('helmet')

var index = require('./routes/index')
var appRouter = require('./routes/app')
var learn = require('./routes/learn')
var signup = require('./routes/signup')
var login = require('./routes/login')
var profile = require('./routes/profile')

var app = express()

// view engine setup
app.set('views', path.join(__dirname, 'views'))
app.set('view engine', 'ejs')

app.use(helmet({
    hsts: false,
    noSniff: true
}))

app.use(function (req, res, next) {
    if (!res.getHeader('X-Frame-Options')) {
        res.setHeader('X-Frame-Options', 'SAMEORIGIN')
    }
    if (!res.getHeader('X-Content-Type-Options')) {
        res.setHeader('X-Content-Type-Options', 'nosniff')
    }
    next()
})

app.use(function (req, res, next) {
    var originalRender = res.render
    res.render = function () {
        if (!res.getHeader('X-Content-Type-Options')) {
            res.setHeader('X-Content-Type-Options', 'nosniff')
        }
        if (!res.getHeader('X-Frame-Options')) {
            res.setHeader('X-Frame-Options', 'SAMEORIGIN')
        }
        return originalRender.apply(this, arguments)
    }
    next()
})

app.use('/', index)
app.use('/app', appRouter(app))
app.use('/learn', learn)
app.use('/signup', signup)
app.use('/login', login)
app.use('/profile', profile)

module.exports = app

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
var appRoutes = require('./routes/app')
var learn = require('./routes/learn')
var signup = require('./routes/signup')
var login = require('./routes/login')
var profile = require('./routes/profile')

var app = express()

// view engine setup
app.set('views', path.join(__dirname, 'views'))
app.set('view engine', 'ejs')

// Security headers should be enforced globally so no route can bypass them.
app.use(helmet.hsts({
    maxAge: 15552000,
    includeSubDomains: true
}))

app.use(function (req, res, next) {
    res.setHeader('X-Frame-Options', 'SAMEORIGIN')
    res.setHeader('X-Content-Type-Options', 'nosniff')
    next()
})

app.use(function (req, res, next) {
    if (!res.getHeader('Content-Security-Policy')) {
        res.setHeader('Content-Security-Policy', "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'")
    }
    next()
})

module.exports = app

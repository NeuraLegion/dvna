var express = require('express')
var path = require('path')
var favicon = require('serve-favicon')
var logger = require('morgan')
var cookieParser = require('cookie-parser')
var bodyParser = require('body-parser')
var session = require('express-session')
var csrf = require('csurf')
var passport = require('passport')
var flash = require('connect-flash')
var MongoStore = require('connect-mongo')(session)
var mongoose = require('mongoose')

var app = express()

function setSecurityHeaders(req, res, next) {
    res.setHeader('X-Frame-Options', 'SAMEORIGIN')
    res.setHeader('X-Content-Type-Options', 'nosniff')
    res.setHeader('Referrer-Policy', 'same-origin')
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' https://maxcdn.bootstrapcdn.com https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://maxcdn.bootstrapcdn.com https://cdnjs.cloudflare.com; img-src 'self' data:; font-src 'self' https://maxcdn.bootstrapcdn.com https://cdnjs.cloudflare.com data:; object-src 'none'; base-uri 'self'; frame-ancestors 'self'")
    next()
}

app.set('views', path.join(__dirname, 'views'))
app.set('view engine', 'ejs')

app.use(logger('dev'))
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(session({
    secret: process.env.SESSION_SECRET || 'keyboard cat',
    resave: false,
    saveUninitialized: false,
    store: new MongoStore({ mongooseConnection: mongoose.connection })
}))
app.use(passport.initialize())
app.use(passport.session())
app.use(flash())

app.use('/app', setSecurityHeaders)
app.use('/app', require('./routes/app')())

module.exports = app

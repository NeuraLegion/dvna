var express = require('express')
var path = require('path')
var session = require('express-session')
var passport = require('passport')
var flash = require('connect-flash')
var appConfig = require('./config/server')

var app = express()

// existing middleware/setup remains unchanged where applicable
app.use(session({
    secret: appConfig.session.secret,
    resave: appConfig.session.resave,
    saveUninitialized: appConfig.session.saveUninitialized,
    proxy: appConfig.session.proxy,
    cookie: {
        httpOnly: appConfig.session.cookie.httpOnly,
        secure: true,
        sameSite: appConfig.session.cookie.sameSite
    }
}))

app.use(passport.initialize())
app.use(passport.session())
app.use(flash())

module.exports = app

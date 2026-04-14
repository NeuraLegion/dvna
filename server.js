var express = require('express')
var session = require('express-session')
var appConfig = require('./config/server')

var app = express()

if (appConfig.session.proxy) {
    app.set('trust proxy', 1)
}

app.use(session({
    secret: appConfig.session.secret,
    resave: appConfig.session.resave,
    saveUninitialized: appConfig.session.saveUninitialized,
    proxy: appConfig.session.proxy,
    cookie: {
        httpOnly: appConfig.session.cookie.httpOnly,
        secure: appConfig.session.cookie.secure ? 'auto' : false,
        sameSite: appConfig.session.cookie.sameSite,
        path: '/'
    }
}))

module.exports = app

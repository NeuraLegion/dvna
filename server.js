var express = require('express')
var session = require('express-session')
var app = express()
var serverConfig = require('./config/server')

if (serverConfig.trustProxy) {
    app.set('trust proxy', 1)
}

app.use(session({
    secret: process.env.SESSION_SECRET || 'change-this-secret',
    resave: false,
    saveUninitialized: false,
    proxy: true,
    cookie: {
        secure: serverConfig.cookieSecure,
        httpOnly: true,
        sameSite: 'lax'
    }
}))

module.exports = app

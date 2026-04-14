var express = require('express')
var session = require('express-session')
var passport = require('passport')
var isHttpsRequest = require('./core/isHttpsRequest')

var app = express()

app.set('trust proxy', 1)

app.use(session({
    secret: process.env.SESSION_SECRET || 'change-me',
    resave: false,
    saveUninitialized: false,
    proxy: true,
    cookie: {
        httpOnly: true,
        sameSite: 'lax',
        secure: function (req) {
            return isHttpsRequest(req)
        }
    }
}))

app.use(passport.initialize())
app.use(passport.session())

module.exports = app

var express = require('express')
var session = require('express-session')
var passport = require('passport')

var app = express()

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: true,
        httpOnly: true,
        sameSite: 'lax'
    }
}))

app.use(passport.initialize())
app.use(passport.session())

module.exports = app

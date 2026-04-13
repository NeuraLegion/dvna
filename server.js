var express = require('express')
var session = require('express-session')
var passport = require('passport')
var cookieParser = require('cookie-parser')

var app = express()

app.use(cookieParser())
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: true,
        httpOnly: true
    }
}))
app.use(passport.initialize())
app.use(passport.session())

module.exports = app

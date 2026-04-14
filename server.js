var express = require('express')
var path = require('path')
var session = require('express-session')
var passport = require('passport')
var flash = require('connect-flash')

var app = express()

// existing middleware/setup remains unchanged where applicable
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        sameSite: 'lax'
    }
}))

app.use(passport.initialize())
app.use(passport.session())
app.use(flash())

module.exports = app

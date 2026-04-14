var express = require('express')
var app = express()
var passport = require('passport')
var session = require('express-session')
var flash = require('connect-flash')

// Security headers
app.use(function (req, res, next) {
    res.setHeader('X-Frame-Options', 'SAMEORIGIN')
    next()
})

app.use(session({
    secret: 'dvna-secret',
    resave: false,
    saveUninitialized: false
}))

app.use(passport.initialize())
app.use(passport.session())
app.use(flash())

module.exports = app

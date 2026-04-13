var express = require('express')
var path = require('path')
var favicon = require('serve-favicon')
var logger = require('morgan')
var cookieParser = require('cookie-parser')
var bodyParser = require('body-parser')
var session = require('express-session')
var passport = require('passport')
var flash = require('connect-flash')
var serverConfig = require('./config/server')

var app = express()

// If TLS is terminated upstream, trust the proxy so secure cookies are honored
// and not downgraded on HTTPS requests.
if (process.env.NODE_ENV === 'production') {
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

app.use(passport.initialize())
app.use(passport.session())
app.use(flash())

module.exports = app

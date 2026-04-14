var express = require('express')
var path = require('path')
var favicon = require('serve-favicon')
var logger = require('morgan')
var cookieParser = require('cookie-parser')
var bodyParser = require('body-parser')
var flash = require('connect-flash')
var session = require('express-session')
var passport = require('passport')

var config = require('./config/server')
var routes = require('./routes')

var app = express()

app.set('trust proxy', 1)

function isHttpsRequest(req) {
    if (req.secure) {
        return true
    }

    var forwardedProto = req.headers['x-forwarded-proto']
    if (typeof forwardedProto === 'string' && forwardedProto.split(',')[0].trim().toLowerCase() === 'https') {
        return true
    }

    return false
}

// Redirect plain HTTP requests before session middleware runs so the session
// cookie is never delivered over an insecure channel.
app.use(function (req, res, next) {
    if (process.env.NODE_ENV === 'production' && !isHttpsRequest(req)) {
        return res.redirect(301, 'https://' + req.headers.host + req.originalUrl)
    }

    next()
})

app.use(favicon(path.join(__dirname, 'public', 'favicon.ico')))
app.use(logger('dev'))
app.use(cookieParser())
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(session(config.session))
app.use(flash())
app.use(passport.initialize())
app.use(passport.session())

app.use('/', routes)

module.exports = app

var express = require('express')
var path = require('path')
var cookieParser = require('cookie-parser')
var logger = require('morgan')
var session = require('express-session')
var flash = require('connect-flash')
var passport = require('passport')

var config = require('./config/server')
var indexRouter = require('./routes/index')
var appRouter = require('./routes/app')

var app = express()

// Behind a proxy/load balancer, Express must trust the proxy so req.secure works
// correctly when the original request was HTTPS.
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

function setSecurityHeaders(req, res, next) {
    res.setHeader('X-Frame-Options', 'SAMEORIGIN')
    res.setHeader('X-Content-Type-Options', 'nosniff')

    // Only emit HSTS on HTTPS responses; browsers ignore it over plain HTTP.
    // The scanner observed the /app/calc path, so setting it here ensures all
    // secure application responses include the header regardless of route flow.
    if (isHttpsRequest(req)) {
        res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
    }

    if (typeof next === 'function') {
        next()
    }
}

app.use(setSecurityHeaders)

app.use(logger('dev'))
app.use(express.json())
app.use(express.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(express.static(path.join(__dirname, 'public')))

app.use(session(config.session))
app.use(passport.initialize())
app.use(passport.session())
app.use(flash())

app.use('/', indexRouter)
app.use('/app', appRouter(app))

module.exports = app

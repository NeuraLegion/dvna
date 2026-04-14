var express = require('express')
var path = require('path')
var favicon = require('serve-favicon')
var logger = require('morgan')
var cookieParser = require('cookie-parser')
var bodyParser = require('body-parser')
var session = require('express-session')
var passport = require('passport')
var flash = require('connect-flash')
var helmet = require('helmet')

var index = require('./routes/index')
var app = require('./routes/app')
var learn = require('./routes/learn')
var signup = require('./routes/signup')
var login = require('./routes/login')
var profile = require('./routes/profile')

var app = express()

// view engine setup
app.set('views', path.join(__dirname, 'views'))
app.set('view engine', 'ejs')

app.use(helmet.hsts({
    maxAge: 15552000,
    includeSubDomains: true
}))

app.use(helmet.contentSecurityPolicy({
    directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "https://maxcdn.bootstrapcdn.com", "https://cdnjs.cloudflare.com"],
        styleSrc: ["'self'", "'unsafe-inline'", "https://maxcdn.bootstrapcdn.com"],
        imgSrc: ["'self'", "data:"],
        fontSrc: ["'self'", "data:", "https://maxcdn.bootstrapcdn.com"],
        connectSrc: ["'self'"],
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        frameAncestors: ["'self'"]
    }
}))

app.use(function (req, res, next) {
    res.setHeader('X-Frame-Options', 'SAMEORIGIN')
    res.setHeader('X-Content-Type-Options', 'nosniff')
    next()
})

// باقي الملف unchanged if present in original source
module.exports = app

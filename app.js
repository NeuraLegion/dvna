var express = require('express')
var path = require('path')
var favicon = require('serve-favicon')
var logger = require('morgan')
var cookieParser = require('cookie-parser')
var bodyParser = require('body-parser')
var flash = require('connect-flash')
var fileUpload = require('express-fileupload')
var session = require('express-session')
var app = express()

// Global hardening: ensure every response includes MIME-sniffing protection.
app.use(function (req, res, next) {
    res.setHeader('X-Content-Type-Options', 'nosniff')
    next()
})

app.use(favicon(path.join(__dirname, 'public', 'favicon.ico')))
app.use(logger('dev'))
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(express.static(path.join(__dirname, 'public')))
app.use(fileUpload())
app.use(session({
    secret: 'secret',
    resave: false,
    saveUninitialized: true
}))
app.use(flash())

app.use(function (req, res, next) {
    // Preserve the existing header even if downstream code attempts to modify response headers.
    if (!res.getHeader('X-Content-Type-Options')) {
        res.setHeader('X-Content-Type-Options', 'nosniff')
    }
    next()
})

app.use('/', require('./routes/index')())
app.use('/app', require('./routes/app')())

module.exports = app

var express = require('express')
var app = express()
var path = require('path')
var fs = require('fs')
var bodyParser = require('body-parser')
var fileUpload = require('express-fileupload')
var session = require('express-session')
var flash = require('connect-flash')
var passport = require('passport')
var helmet = require('helmet')

// Security headers
app.use(function (req, res, next) {
    res.setHeader('X-Frame-Options', 'SAMEORIGIN')
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' https://maxcdn.bootstrapcdn.com https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://maxcdn.bootstrapcdn.com; img-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'self'")
    next()
})

app.use(bodyParser.urlencoded({ extended: false }))
app.use(bodyParser.json())
app.use(fileUpload())
app.use(session({
    secret: 'keyboard cat',
    resave: false,
    saveUninitialized: false
}))
app.use(flash())
app.use(passport.initialize())
app.use(passport.session())

app.set('view engine', 'ejs')
app.set('views', path.join(__dirname, 'views'))

app.use('/assets', express.static(path.join(__dirname, 'assets')))

app.use('/app', require('./routes/app')())

module.exports = app

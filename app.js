var express = require('express')
var path = require('path')
var favicon = require('serve-favicon')
var logger = require('morgan')
var cookieParser = require('cookie-parser')
var bodyParser = require('body-parser')
var flash = require('connect-flash')
var session = require('express-session')
var fileUpload = require('express-fileupload')

var index = require('./routes/index')
var appRoutes = require('./routes/app')
var authRoutes = require('./routes/auth')

var app = express()

// Security headers must be applied at the app layer so every response,
// including redirects, error responses, and any route handler that does not
// explicitly set them, receives clickjacking protection.
app.use(function (req, res, next) {
  res.setHeader('X-Frame-Options', 'SAMEORIGIN')
  res.setHeader('X-Content-Type-Options', 'nosniff')
  res.setHeader('Content-Security-Policy', "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'")
  next()
})

app.set('views', path.join(__dirname, 'views'))
app.set('view engine', 'ejs')

app.use(favicon(path.join(__dirname, 'public', 'favicon.ico')))
app.use(logger('dev'))
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(session({
  secret: process.env.SESSION_SECRET || 'change-me-in-production',
  resave: false,
  saveUninitialized: false
}))
app.use(flash())
app.use(fileUpload())
app.use(express.static(path.join(__dirname, 'public')))

app.use('/', index)
app.use('/app', appRoutes())
app.use('/auth', authRoutes())

// Error handling should preserve security headers from the top-level middleware.
app.use(function (req, res, next) {
  next()
})

module.exports = app

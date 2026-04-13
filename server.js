var express = require('express')
var app = express()
var path = require('path')
var fs = require('fs')
var https = require('https')
var logger = require('morgan')
var favicon = require('serve-favicon')
var cookieParser = require('cookie-parser')
var bodyParser = require('body-parser')
var session = require('express-session')
var flash = require('connect-flash')
var hsts = require('hsts')
var expressSanitizer = require('express-sanitizer')
var csrf = require('csurf')

var routes = require('./routes/index')
var user = require('./routes/user')
var appRoutes = require('./routes/app')
var health = require('./routes/health')

app.use(function (req, res, next) {
  res.setHeader('Content-Security-Policy', "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'self'; img-src 'self' data:; font-src 'self' data: https://maxcdn.bootstrapcdn.com; style-src 'self' 'unsafe-inline' https://maxcdn.bootstrapcdn.com; script-src 'self' https://maxcdn.bootstrapcdn.com https://cdnjs.cloudflare.com; connect-src 'self'; form-action 'self'")
  next()
})

app.use(hsts({
  maxAge: 31536000,
  includeSubdomains: true,
  force: true
}))

app.use(favicon(path.join(__dirname, 'public', 'favicon.ico')))
app.use(logger('dev'))
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(session({
  secret: 'dvna-session-secret',
  resave: false,
  saveUninitialized: false
}))
app.use(flash())
app.use(expressSanitizer())
app.use(csrf())

app.use(express.static(path.join(__dirname, 'public')))

app.use('/', routes())
app.use('/user', user())
app.use('/app', appRoutes())
app.use('/health', health())

module.exports = app

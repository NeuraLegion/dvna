var express = require('express')
var path = require('path')
var cookieParser = require('cookie-parser')
var bodyParser = require('body-parser')
var session = require('express-session')
var flash = require('connect-flash')
var passport = require('passport')
var helmet = require('helmet')

var app = express()

app.set('trust proxy', 1)
app.set('view engine', 'ejs')
app.set('views', path.join(__dirname, 'views'))

app.use(helmet({
  xssFilter: false,
  noSniff: true,
  frameguard: {
    action: 'sameorigin'
  }
}))

app.use(function (req, res, next) {
  res.setHeader('X-Frame-Options', 'SAMEORIGIN')
  res.setHeader('X-Content-Type-Options', 'nosniff')
  res.setHeader('Referrer-Policy', 'same-origin')
  next()
})

app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(session({
  secret: process.env.SESSION_SECRET || 'change-me',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: 'auto'
  }
}))
app.use(flash())
app.use(passport.initialize())
app.use(passport.session())

require('./routes/app')(app)

module.exports = app

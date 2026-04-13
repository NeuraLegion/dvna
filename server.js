var express = require('express')
var path = require('path')
var favicon = require('serve-favicon')
var logger = require('morgan')
var cookieParser = require('cookie-parser')
var bodyParser = require('body-parser')
var flash = require('connect-flash')
var session = require('express-session')
var passport = require('passport')
var app = express()

require('./core/passport')(passport)
var routes = require('./routes/main')(passport)

app.set('views', path.join(__dirname, 'views'))
app.set('view engine', 'ejs')

// Trust the reverse proxy in production so req.secure reflects the original HTTPS request.
if (process.env.NODE_ENV === 'production') {
  app.set('trust proxy', 1)
}

app.use(favicon(path.join(__dirname, 'public', 'favicon.ico')))
app.use(logger('dev'))
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(express.static(path.join(__dirname, 'public')))

app.use(session({
  secret: process.env.SESSION_SECRET || 'change_this_session_secret',
  resave: false,
  saveUninitialized: false,
  proxy: process.env.NODE_ENV === 'production',
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    sameSite: 'lax'
  }
}))

app.use(flash())
app.use(passport.initialize())
app.use(passport.session())

app.use('/', routes)

module.exports = app

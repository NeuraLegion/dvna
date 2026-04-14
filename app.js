var createError = require('http-errors')
var express = require('express')
var path = require('path')
var cookieParser = require('cookie-parser')
var logger = require('morgan')
var flash = require('connect-flash')
var session = require('express-session')
var fileUpload = require('express-fileupload')
var passport = require('passport')

var indexRouter = require('./routes/index')
var appRouter = require('./routes/app')
var authRouter = require('./routes/auth')
var apiRouter = require('./routes/api')

var app = express()

app.set('trust proxy', 1)
app.set('view engine', 'ejs')
app.set('views', path.join(__dirname, 'views'))
app.set('env', process.env.NODE_ENV || 'development')

// Enforce MIME-sniffing protection for every response, regardless of route/middleware path.
app.use(function (req, res, next) {
  res.setHeader('X-Content-Type-Options', 'nosniff')
  next()
})

app.use(logger('dev'))
app.use(express.json())
app.use(express.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(express.static(path.join(__dirname, 'public')))
app.use(fileUpload())
app.use(session({
  secret: process.env.SESSION_SECRET || 'development-session-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production'
  }
}))
app.use(passport.initialize())
app.use(passport.session())
app.use(flash())

app.use('/', indexRouter)
app.use('/auth', authRouter)
app.use('/app', appRouter)
app.use('/api', apiRouter)

// catch 404 and forward to error handler
app.use(function (req, res, next) {
  next(createError(404))
})

// error handler
app.use(function (err, req, res, next) {
  res.locals.message = err.message
  res.locals.error = req.app.get('env') === 'development' ? err : {}

  if (!res.headersSent) {
    res.setHeader('X-Content-Type-Options', 'nosniff')
  }

  res.status(err.status || 500)
  res.render('error')
})

module.exports = app

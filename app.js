var express = require('express')
var path = require('path')
var cookieParser = require('cookie-parser')
var logger = require('morgan')
var createError = require('http-errors')

var indexRouter = require('./routes/index')
var appRouter = require('./routes/app')
var usersRouter = require('./routes/users')
var apiRouter = require('./routes/api')

var app = express()

// Trust reverse proxies so secure headers and redirects work correctly
// when HTTPS is terminated upstream (for example, at a load balancer).
app.set('trust proxy', 1)

app.use(function (req, res, next) {
    res.setHeader('X-Frame-Options', 'SAMEORIGIN')
    res.setHeader('X-Content-Type-Options', 'nosniff')

    // Send HSTS only when the request is secure. When the app is behind a
    // proxy, trust proxy allows req.secure to reflect the original protocol.
    if (req.secure) {
        res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
    }

    next()
})

app.use(logger('dev'))
app.use(express.json())
app.use(express.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(express.static(path.join(__dirname, 'public')))

app.use('/', indexRouter)
app.use('/app', appRouter())
app.use('/users', usersRouter)
app.use('/api', apiRouter)

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404))
})

// error handler
app.use(function(err, req, res, next) {
  res.locals.message = err.message
  res.locals.error = req.app.get('env') === 'development' ? err : {}

  res.status(err.status || 500)
  res.render('error')
})

module.exports = app

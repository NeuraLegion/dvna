var createError = require('http-errors')
var express = require('express')
var path = require('path')
var cookieParser = require('cookie-parser')
var logger = require('morgan')
var session = require('express-session')
var flash = require('connect-flash')
var passport = require('passport')
var LocalStrategy = require('passport-local').Strategy

var indexRouter = require('./routes/index')
var mainRouter = require('./routes/main')

var app = express()

// Anti-clickjacking protection
app.use(function (req, res, next) {
	res.setHeader('X-Frame-Options', 'SAMEORIGIN')
	next()
})

app.use(logger('dev'))
app.use(express.json())
app.use(express.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(express.static(path.join(__dirname, 'public')))

app.use(session({
	secret: process.env.SESSION_SECRET || 'keyboard cat',
	resave: false,
	saveUninitialized: false
}))
app.use(flash())
app.use(passport.initialize())
app.use(passport.session())

app.use('/', indexRouter)
app.use('/', mainRouter(passport))

// catch 404 and forward to error handler
app.use(function (req, res, next) {
	next(createError(404))
})

// error handler
app.use(function (err, req, res, next) {
	res.locals.message = err.message
	res.locals.error = req.app.get('env') === 'development' ? err : {}

	res.status(err.status || 500)
	res.render('error')
})

module.exports = app

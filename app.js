var express = require('express')
var path = require('path')
var favicon = require('serve-favicon')
var logger = require('morgan')
var cookieParser = require('cookie-parser')
var bodyParser = require('body-parser')
var session = require('express-session')
var passport = require('passport')
var flash = require('connect-flash')

var index = require('./routes/index')
var appRouter = require('./routes/app')
var learn = require('./routes/learn')
var signup = require('./routes/signup')
var login = require('./routes/login')
var profile = require('./routes/profile')

var app = express()

// view engine setup
app.set('views', path.join(__dirname, 'views'))
app.set('view engine', 'ejs')

// Global security headers applied before all routes so every response path,
// including auth failures, redirects, renders, and /app/calc, gets nosniff.
app.use(function (req, res, next) {
	res.setHeader('X-Content-Type-Options', 'nosniff')
	next()
})

app.use(function (req, res, next) {
	if (!res.getHeader('X-Frame-Options')) {
		res.setHeader('X-Frame-Options', 'SAMEORIGIN')
	}
	next()
})

app.use(function (req, res, next) {
	if (!res.getHeader('Content-Security-Policy')) {
		res.setHeader('Content-Security-Policy', "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'")
	}
	next()
})

app.use(logger('dev'))
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(session({
	secret: process.env.SESSION_SECRET || 'change-me-in-production',
	resave: false,
	saveUninitialized: false
}))
app.use(passport.initialize())
app.use(passport.session())
app.use(flash())

app.use(express.static(path.join(__dirname, 'public')))

app.use('/', index)
app.use('/app', appRouter(app))
app.use('/learn', learn)
app.use('/signup', signup)
app.use('/login', login)
app.use('/profile', profile)

// catch 404 and forward to error handler
app.use(function (req, res, next) {
	var err = new Error('Not Found')
	err.status = 404
	next(err)
})

// error handlers
app.use(function (err, req, res, next) {
	res.status(err.status || 500)
	res.setHeader('X-Content-Type-Options', 'nosniff')
	res.render('error', {
		message: err.message,
		error: req.app.get('env') === 'development' ? err : {}
	})
})

module.exports = app

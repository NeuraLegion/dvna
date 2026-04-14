var express = require('express')
var path = require('path')
var cookieParser = require('cookie-parser')
var logger = require('morgan')
var passport = require('passport')
var session = require('express-session')
var flash = require('connect-flash')

var indexRouter = require('./routes/main')(passport)
var authRouter = require('./routes/auth')(passport)

var app = express()

var cspHeaderValue = "default-src 'self'; script-src 'self' https://maxcdn.bootstrapcdn.com https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://maxcdn.bootstrapcdn.com; img-src 'self' data:; font-src 'self' https://maxcdn.bootstrapcdn.com; object-src 'none'; base-uri 'self'; frame-ancestors 'self'"

app.use(function (req, res, next) {
	res.setHeader('Content-Security-Policy', cspHeaderValue)
	next()
})

app.use(logger('dev'))
app.use(express.json())
app.use(express.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(express.static(path.join(__dirname, 'public')))

app.use(session({
	secret: process.env.SESSION_SECRET || 'secret',
	resave: false,
	saveUninitialized: false
}))
app.use(passport.initialize())
app.use(passport.session())
app.use(flash())

app.use('/', indexRouter)
app.use('/auth', authRouter)

app.use(function (req, res, next) {
	res.status(404)
	res.render('404')
})

module.exports = app

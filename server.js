var express = require('express')
var path = require('path')
var logger = require('morgan')
var cookieParser = require('cookie-parser')
var bodyParser = require('body-parser')
var session = require('express-session')
var passport = require('passport')
var flash = require('connect-flash')

var app = express()
var isProduction = process.env.NODE_ENV === 'production'
var isHttps = function (req) {
	return req.secure || req.headers['x-forwarded-proto'] === 'https'
}

app.set('views', path.join(__dirname, 'views'))
app.set('view engine', 'ejs')

app.use(logger('dev'))
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(express.static(path.join(__dirname, 'public')))

app.use(function (req, res, next) {
	var requestIsHttps = isHttps(req)

	res.cookie = (function (origCookie) {
		return function (name, value, options) {
			options = options || {}
			if (options.secure === undefined) {
				options.secure = requestIsHttps || isProduction
			}
			return origCookie.call(this, name, value, options)
		}
	})(res.cookie)

	next()
})

app.use(session({
	secret: process.env.SESSION_SECRET || 'change-this-secret',
	resave: false,
	saveUninitialized: false,
	cookie: {
		secure: isProduction,
		httpOnly: true,
		sameSite: 'lax'
	}
}))

app.use(passport.initialize())
app.use(passport.session())
app.use(flash())

app.use(function (req, res, next) {
	res.locals.success = req.flash('success')
	res.locals.error = req.flash('error')
	next()
})

app.use('/', require('./routes/main')(passport))

module.exports = app

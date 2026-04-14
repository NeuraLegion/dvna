var express = require('express')
var path = require('path')
var favicon = require('serve-favicon')
var logger = require('morgan')
var cookieParser = require('cookie-parser')
var bodyParser = require('body-parser')
var session = require('express-session')
var passport = require('passport')
var flash = require('connect-flash')
var helmet = require('helmet')

var routes = require('./routes/main')
var authHandler = require('./core/authHandler')

var app = express()

app.set('views', path.join(__dirname, 'views'))
app.set('view engine', 'ejs')

app.use(helmet())
app.use(helmet.noSniff())
app.use(helmet.contentSecurityPolicy({
	useDefaults: true,
	directives: {
		defaultSrc: ["'self'"],
		styleSrc: ["'self'", 'https://maxcdn.bootstrapcdn.com', 'https://cdnjs.cloudflare.com'],
		scriptSrc: ["'self'", 'https://maxcdn.bootstrapcdn.com', 'https://cdnjs.cloudflare.com']
	}
}))
app.use(helmet.hsts({
	maxAge: 15552000,
	includeSubDomains: true
}))

app.use(logger('dev'))
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(session({
	secret: process.env.SESSION_SECRET || 'dev-secret',
	resave: false,
	saveUninitialized: false
}))
app.use(passport.initialize())
app.use(passport.session())
app.use(flash())

app.use(express.static(path.join(__dirname, 'public')))

app.use(function (req, res, next) {
	res.locals.messages = {
		success: req.flash('success'),
		danger: req.flash('danger'),
		warning: req.flash('warning'),
		info: req.flash('info')
	}
	next()
})

app.use('/', routes(passport))

app.use(function (req, res, next) {
	var err = new Error('Not Found')
	err.status = 404
	next(err)
})

app.use(function (err, req, res, next) {
	res.status(err.status || 500)
	res.render('error', {
		message: err.message,
		error: req.app.get('env') === 'development' ? err : {}
	})
})

module.exports = app

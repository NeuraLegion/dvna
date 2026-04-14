var express = require('express')
var path = require('path')
var favicon = require('serve-favicon')
var logger = require('morgan')
var cookieParser = require('cookie-parser')
var bodyParser = require('body-parser')
var flash = require('connect-flash')
var session = require('express-session')
var passport = require('passport')
var expressValidator = require('express-validator')

var app = express()

app.set('trust proxy', 1)

app.set('views', path.join(__dirname, 'views'))
app.set('view engine', 'ejs')

app.use(function (req, res, next) {
	res.setHeader('X-Frame-Options', 'SAMEORIGIN')
	if (req.secure || req.headers['x-forwarded-proto'] === 'https') {
		res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
	}
	res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' https://maxcdn.bootstrapcdn.com https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://maxcdn.bootstrapcdn.com; img-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'self'")
	res.setHeader('X-Content-Type-Options', 'nosniff')
	next()
})

app.use(favicon(path.join(__dirname, 'public', 'favicon.ico')))
app.use(logger('dev'))
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(expressValidator())
app.use(express.static(path.join(__dirname, 'public')))
app.use(session({
	secret: process.env.SESSION_SECRET || 'dev-secret',
	resave: false,
	saveUninitialized: false,
	cookie: {
		httpOnly: true,
		secure: process.env.NODE_ENV === 'production',
		sameSite: 'lax'
	}
}))
app.use(flash())
app.use(passport.initialize())
app.use(passport.session())

require('./config/passport')(passport)

app.use('/', require('./routes/main')(passport))

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

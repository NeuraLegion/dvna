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

var routes = require('./routes/main')(passport)
var app = express()

app.use(function (req, res, next) {
	res.setHeader('X-Frame-Options', 'SAMEORIGIN')
	res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
	res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' https://maxcdn.bootstrapcdn.com https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://maxcdn.bootstrapcdn.com; img-src 'self' data:; font-src 'self' https://maxcdn.bootstrapcdn.com; object-src 'none'; base-uri 'self'; frame-ancestors 'self'")
	next()
})

app.set('views', path.join(__dirname, 'views'))
app.set('view engine', 'ejs')

app.use(favicon(path.join(__dirname, 'public', 'favicon.ico')))
app.use(logger('dev'))
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(session({
	secret: 'secret',
	resave: false,
	saveUninitialized: false
}))
app.use(passport.initialize())
app.use(passport.session())
app.use(flash())
app.use(express.static(path.join(__dirname, 'public')))

app.use('/', routes)

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

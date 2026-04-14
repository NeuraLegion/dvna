var express = require('express')
var path = require('path')
var favicon = require('serve-favicon')
var logger = require('morgan')
var cookieParser = require('cookie-parser')
var bodyParser = require('body-parser')
var flash = require('connect-flash')
var session = require('express-session')
var fileUpload = require('express-fileupload')

var app = express()

app.set('views', path.join(__dirname, 'views'))
app.set('view engine', 'ejs')

// Ensure security headers are applied to every response, including routes that
// may bypass router-level middleware, redirects, or error responses.
app.use(function (req, res, next) {
	res.setHeader('X-Content-Type-Options', 'nosniff')
	next()
})

app.use(favicon(path.join(__dirname, 'public', 'favicon.ico')))
app.use(logger('dev'))
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(session({
	secret: process.env.SESSION_SECRET || 'change-me-in-production',
	resave: false,
	saveUninitialized: false
}))
app.use(flash())
app.use(fileUpload())
app.use(express.static(path.join(__dirname, 'public')))

require('./routes')(app)

// Preserve explicit header setting on error responses as well.
app.use(function (req, res, next) {
	res.status(404)
	res.setHeader('X-Content-Type-Options', 'nosniff')
	res.render('error', {
		message: 'Not Found',
		error: {}
	})
})

app.use(function (err, req, res, next) {
	res.status(err.status || 500)
	res.setHeader('X-Content-Type-Options', 'nosniff')
	res.render('error', {
		message: err.message,
		error: app.get('env') === 'development' ? err : {}
	})
})

module.exports = app

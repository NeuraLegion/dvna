var express = require('express')
var path = require('path')
var cookieParser = require('cookie-parser')
var bodyParser = require('body-parser')
var logger = require('morgan')
var session = require('express-session')
var csrf = require('csurf')

var index = require('./routes/index')
var appRoutes = require('./routes/app')
var apiRoutes = require('./routes/api')
var authHandler = require('./core/authHandler')

var app = express()

function setSecurityHeaders(req, res, next) {
	res.setHeader('X-Frame-Options', 'SAMEORIGIN')
	res.setHeader('X-Content-Type-Options', 'nosniff')
	res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
	if (!res.getHeader('Content-Security-Policy')) {
		res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' https://maxcdn.bootstrapcdn.com https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://maxcdn.bootstrapcdn.com https://cdnjs.cloudflare.com; img-src 'self' data:; font-src 'self' https://maxcdn.bootstrapcdn.com https://cdnjs.cloudflare.com data:; object-src 'none'; base-uri 'self'; frame-ancestors 'self'")
	}
	return next()
}

app.use(setSecurityHeaders)
app.use(logger('dev'))
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(express.static(path.join(__dirname, 'public')))

app.set('views', path.join(__dirname, 'views'))
app.set('view engine', 'ejs')

app.use('/', index())
app.use('/app', appRoutes())
app.use('/api', apiRoutes())

app.use(function (req, res, next) {
	var err = new Error('Not Found')
	err.status = 404
	next(err)
})

app.use(function (err, req, res, next) {
	res.locals.message = err.message
	res.locals.error = req.app.get('env') === 'development' ? err : {}
	res.status(err.status || 500)
	res.render('error')
})

module.exports = app

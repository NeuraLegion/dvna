var express = require('express')
var app = express()
var path = require('path')
var logger = require('morgan')
var cookieParser = require('cookie-parser')
var bodyParser = require('body-parser')
var flash = require('express-flash')
var session = require('express-session')
var passport = require('passport')

var main = require('./routes/main')
var authHandler = require('./core/authHandler')

app.use(logger('dev'))
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(express.static(path.join(__dirname, 'public')))

app.use(function (req, res, next) {
	res.setHeader('X-Content-Type-Options', 'nosniff')
	next()
})

app.use(session({
	secret: 'dvanonsecret',
	resave: false,
	saveUninitialized: false,
	cookie: {
		httpOnly: true,
		secure: true,
		sameSite: 'lax'
	}
}))
app.use(flash())
app.use(passport.initialize())
app.use(passport.session())

app.use(function (req, res, next) {
	res.setHeader('X-Frame-Options', 'SAMEORIGIN')
	res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
	res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' https://maxcdn.bootstrapcdn.com https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://maxcdn.bootstrapcdn.com; img-src 'self' data:; font-src 'self' https://maxcdn.bootstrapcdn.com; object-src 'none'; base-uri 'self'; frame-ancestors 'self'")
	next()
})

app.set('views', path.join(__dirname, 'views'))
app.set('view engine', 'ejs')

app.use('/', main(passport))

app.use(function (req, res) {
	res.status(404).send('404')
})

app.use(function (err, req, res, next) {
	console.log(err)
	res.status(500).send('500')
})

module.exports = app

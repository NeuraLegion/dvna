var express = require('express')
var path = require('path')
var logger = require('morgan')
var cookieParser = require('cookie-parser')
var bodyParser = require('body-parser')
var session = require('express-session')
var passport = require('passport')
var flash = require('connect-flash')

var app = express()

app.set('trust proxy', 1)

app.use(function (req, res, next) {
	if (!res.getHeader('Strict-Transport-Security')) {
		res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
	}

	if (!res.getHeader('X-Frame-Options')) {
		res.setHeader('X-Frame-Options', 'SAMEORIGIN')
	}

	next()
})

app.use(logger('dev'))
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(express.static(path.join(__dirname, 'public')))

app.set('views', path.join(__dirname, 'views'))
app.set('view engine', 'ejs')

app.use(session({
	secret: 'keyboard cat',
	resave: false,
	saveUninitialized: false
}))
app.use(flash())
app.use(passport.initialize())
app.use(passport.session())

app.use('/', require('./routes/main')(passport))
app.use('/app', require('./routes/app'))

app.use(function (req, res, next) {
	res.status(404).render('404')
})

module.exports = app

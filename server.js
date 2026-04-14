var express = require('express')
var path = require('path')
var logger = require('morgan')
var cookieParser = require('cookie-parser')
var bodyParser = require('body-parser')
var session = require('express-session')
var passport = require('passport')
var flash = require('connect-flash')

var app = express()

app.use(function (req, res, next) {
	res.setHeader('X-Frame-Options', 'SAMEORIGIN')
	res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
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

app.use(function (req, res, next) {
	res.status(404).render('404')
})

module.exports = app

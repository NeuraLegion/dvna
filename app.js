var express = require('express')
var path = require('path')
var logger = require('morgan')
var cookieParser = require('cookie-parser')
var bodyParser = require('body-parser')
var expressSession = require('express-session')
var flash = require('connect-flash')
var passport = require('passport')
var app = express()

require('./config/passport')(passport)

app.set('views', path.join(__dirname, 'views'))
app.set('view engine', 'ejs')

app.use(logger('dev'))
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(expressSession({
	secret: process.env.SESSION_SECRET || 'secret',
	resave: false,
	saveUninitialized: false,
	cookie: {
		httpOnly: true,
		sameSite: 'lax'
	}
}))
app.use(flash())
app.use(passport.initialize())
app.use(passport.session())

app.use(function (req, res, next) {
	res.setHeader('X-Frame-Options', 'SAMEORIGIN')
	next()
})

app.use('/', require('./routes/main')(passport))
app.use(express.static(path.join(__dirname, 'public')))

module.exports = app
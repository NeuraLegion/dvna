var express = require('express')
var path = require('path')
var bodyParser = require('body-parser')
var session = require('express-session')
var flash = require('connect-flash')
var passport = require('passport')
var cookieParser = require('cookie-parser')
var morgan = require('morgan')
var helmet = require('helmet')

var app = express()

app.use(helmet())
app.use(function (req, res, next) {
	res.setHeader('X-Frame-Options', 'SAMEORIGIN')
	next()
})

app.use(morgan('dev'))
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(session({
	secret: 'dvna-secret',
	resave: false,
	saveUninitialized: false,
	cookie: {
		httpOnly: true,
		secure: true
	}
}))
app.use(flash())
app.use(passport.initialize())
app.use(passport.session())
app.use(express.static(path.join(__dirname, 'public')))

module.exports = app

var express = require('express')
var app = express()
var session = require('express-session')
var passport = require('passport')
var cookieParser = require('cookie-parser')
var bodyParser = require('body-parser')

// Security headers
app.use(function (req, res, next) {
	res.setHeader('X-Frame-Options', 'SAMEORIGIN')
	next()
})

app.use(cookieParser())
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(session({
	secret: process.env.SESSION_SECRET || 'secret',
	resave: false,
	saveUninitialized: false
}))
app.use(passport.initialize())
app.use(passport.session())

app.use(express.static('public'))

module.exports = app

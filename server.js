var express = require('express')
var path = require('path')
var fs = require('fs')
var session = require('express-session')
var mongoose = require('mongoose')
var passport = require('passport')
var flash = require('connect-flash')
var bodyParser = require('body-parser')
var methodOverride = require('method-override')
var app = express()

require('./config/passport')(passport)
require('./config/mongoose')

var port = process.env.PORT || 3000

app.use(express.static(path.join(__dirname, 'public')))
app.use(bodyParser.urlencoded({extended: true}))
app.use(bodyParser.json())
app.use(methodOverride())
app.use(flash())

app.set('view engine', 'ejs')
app.set('views', path.join(__dirname, 'views'))
app.set('trust proxy', 1)

var sessionCookie = {
	httpOnly: true,
	sameSite: 'lax',
	secure: true
}

app.use(session({
	secret: process.env.SESSION_SECRET || 'change-me',
	resave: false,
	saveUninitialized: false,
	cookie: sessionCookie
}))

app.use(passport.initialize())
app.use(passport.session())

app.use(function (req, res, next) {
	res.locals.messages = req.flash()
	next()
})

app.use('/', require('./routes/main')(passport))

app.listen(port, function () {
	console.log('Server listening on port ' + port)
})

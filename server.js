var express = require('express')
var path = require('path')
var session = require('express-session')
var flash = require('connect-flash')
var helmet = require('helmet')
var MongoStore = require('connect-mongo')
var app = express()

app.use(function (req, res, next) {
	res.setHeader('X-Frame-Options', 'SAMEORIGIN')
	res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
	res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' https://maxcdn.bootstrapcdn.com https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://maxcdn.bootstrapcdn.com; img-src 'self' data:; font-src 'self' https://maxcdn.bootstrapcdn.com; object-src 'none'; base-uri 'self'; frame-ancestors 'self'")
	next()
})

app.use(express.static(path.join(__dirname, 'public')))
app.use(express.urlencoded({ extended: false }))
app.use(express.json())
app.use(session({
	secret: process.env.SESSION_SECRET || 'secret',
	resave: false,
	saveUninitialized: false,
	cookie: {
		httpOnly: true,
		secure: true,
		sameSite: 'lax'
	},
	store: new MongoStore({
		mongoUrl: process.env.MONGODB_URI
	})
}))
app.use(flash())

module.exports = app

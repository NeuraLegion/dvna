var express = require('express')
var path = require('path')
var cookieParser = require('cookie-parser')
var logger = require('morgan')
var helmet = require('helmet')

var indexRouter = require('./routes/index')
var appRouter = require('./routes/app')

var app = express()

app.set('trust proxy', true)

app.use(helmet({
	strictTransportSecurity: {
		maxAge: 31536000,
		includeSubDomains: true,
		preload: false
	}
}))

app.use(logger('dev'))
app.use(express.json())
app.use(express.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(express.static(path.join(__dirname, 'public')))

app.use('/', indexRouter)
app.use('/app', appRouter())

app.use(function (req, res, next) {
	res.status(404)
	res.render('404')
})

module.exports = app

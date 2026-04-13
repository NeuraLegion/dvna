var express = require('express')
var path = require('path')
var cookieParser = require('cookie-parser')
var bodyParser = require('body-parser')
var compression = require('compression')

var app = express()

app.disable('x-powered-by')

app.use(function (req, res, next) {
    res.setHeader('X-Content-Type-Options', 'nosniff')
    next()
})

app.use(compression())
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(express.static(path.join(__dirname, 'public')))

app.use(function (req, res, next) {
    if (req.secure || req.get('X-Forwarded-Proto') === 'https') {
        res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
    }
    next()
})

module.exports = app

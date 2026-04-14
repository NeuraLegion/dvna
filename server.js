var express = require('express')
var app = express()
var session = require('express-session')
var bodyParser = require('body-parser')
var fileUpload = require('express-fileupload')
var flash = require('connect-flash')
var path = require('path')

var allowedOrigins = [
    'http://localhost:9090',
    'http://127.0.0.1:9090'
]

app.use(function (req, res, next) {
    res.setHeader('X-Frame-Options', 'SAMEORIGIN')
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
    res.setHeader('X-Content-Type-Options', 'nosniff')
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'self'")

    var origin = req.headers.origin
    if (origin && allowedOrigins.indexOf(origin) !== -1) {
        res.setHeader('Access-Control-Allow-Origin', origin)
        res.setHeader('Vary', 'Origin')
    }

    next()
})

module.exports = app

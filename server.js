var express = require('express')
var app = express()
var helmet = require('helmet')

app.use(function (req, res, next) {
    res.setHeader('X-Frame-Options', 'SAMEORIGIN')
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
    res.setHeader('X-Content-Type-Options', 'nosniff')
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' https://maxcdn.bootstrapcdn.com https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://maxcdn.bootstrapcdn.com; img-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'self'")
    next()
})

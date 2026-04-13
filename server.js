var path = require('path')
var express = require('express')
var hsts = require('hsts')

var app = express()

app.use(function (req, res, next) {
  res.setHeader('Content-Security-Policy', "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'self'; img-src 'self' data:; font-src 'self' data: https://maxcdn.bootstrapcdn.com; style-src 'self' 'unsafe-inline' https://maxcdn.bootstrapcdn.com; script-src 'self' https://maxcdn.bootstrapcdn.com https://cdnjs.cloudflare.com; connect-src 'self'; form-action 'self'")
  res.setHeader('X-Content-Type-Options', 'nosniff')
  next()
})

app.use(hsts({
  maxAge: 15552000,
  includeSubDomains: true,
  force: true
}))

module.exports = app

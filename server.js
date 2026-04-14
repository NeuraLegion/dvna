var express = require('express')
var app = express()
var config = require('./config/server')

app.use(function (req, res, next) {
    res.setHeader('X-Frame-Options', 'SAMEORIGIN')
    next()
})

module.exports = app

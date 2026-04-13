var express = require('express')
var app = express()

app.use(function (req, res, next) {
    res.setHeader('X-Frame-Options', 'SAMEORIGIN')
    next()
})

// existing middleware and route registration remain unchanged

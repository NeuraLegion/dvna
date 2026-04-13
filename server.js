var http = require('http')
var app = require('./app')
var serverConfig = require('./config/server')

http.createServer(app).listen(serverConfig.port, serverConfig.listen, function () {
	console.log('Server listening on %s:%s', serverConfig.listen, serverConfig.port)
})

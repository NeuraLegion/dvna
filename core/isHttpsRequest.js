module.exports = function isHttpsRequest(req) {
    if (!req) {
        return false
    }

    if (req.secure) {
        return true
    }

    var forwardedProto = req.headers && req.headers['x-forwarded-proto']
    if (typeof forwardedProto === 'string') {
        return forwardedProto.split(',')[0].trim().toLowerCase() === 'https'
    }

    return false
}

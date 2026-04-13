var db = require('../models')
var bCrypt = require('bcrypt')
const execFile = require('child_process').execFile;
var mathjs = require('mathjs')
var libxmljs = require("libxmljs");
var serialize = require("node-serialize")
const Op = db.Sequelize.Op

function isValidPingTarget(address) {
	if (typeof address !== 'string') {
		return false
	}
	address = address.trim()
	if (!address) {
		return false
	}
	return /^[a-zA-Z0-9.:-]+$/.test(address)
}

function logDatabaseError(message, err) {
	console.error(message)
	if (err) {
		console.error(err)
	}
}

function setResponseSecurityHeaders(res) {
	res.setHeader('X-Frame-Options', 'SAMEORIGIN')
	res.setHeader('X-Content-Type-Options', 'nosniff')
	res.setHeader('Content-Security-Policy', "default-src 'self'; frame-ancestors 'self'")
}

function renderWithGenericError(req, res, view, renderData, message) {
	if (req && typeof req.flash === 'function') {
		req.flash('danger', message)
	}

	setResponseSecurityHeaders(res)
	res.status(200).render(view, renderData)
}

module.exports.userSearch = function (req, res) {
	var query = "SELECT name,id FROM Users WHERE login='" + req.body.login + "'"
	db.sequelize.query(query, {
		model: db.User
	}).then(user => {
		if (user.length) {
			var output = {
				user: {
					name: user[0].name,
					id: user[0].id
				}
			}
			setResponseSecurityHeaders(res)
			res.render('app/usersearch', {
				output: output
			})
		} else {
			req.flash('warning', 'User not found')
			setResponseSecurityHeaders(res)
			res.render('app/usersearch', {
				output: null
			})
		}
	}).catch(err => {
		logDatabaseError('Failed to execute user search query:', err)
		renderWithGenericError(req, res, 'app/usersearch', {
			output: null
		}, 'Internal Error')
	})
}

module.exports.ping = function (req, res) {
	const address = req.body.address

	if (!isValidPingTarget(address)) {
		setResponseSecurityHeaders(res)
		return res.render('app/ping', {
			output: 'Invalid address'
		})
	}

	execFile('ping', ['-c', '2', address], function (err, stdout, stderr) {
		var output = stdout + stderr
		setResponseSecurityHeaders(res)
		res.render('app/ping', {
			output: output
		})
	})
}

module.exports.listProducts = function (req, res) {
	db.Product.findAll().then(products => {
		output = {
			products: products
		}
		setResponseSecurityHeaders(res)
		res.render('app/products', {
			output: output
		})
	})
}

module.exports.productSearch = function (req, res) {
	var searchTerm = typeof req.body.name === 'string' ? req.body.name : ''

	db.Product.findAll({
		where: {
			name: {
				[Op.like]: '%' + searchTerm + '%'
			}
		}
	}).then(products => {
		output = {
			products: products,
			searchTerm: searchTerm
		}
		setResponseSecurityHeaders(res)
		res.render('app/products', {
			output: output
		})
	}).catch(err => {
		logDatabaseError('Failed to search products:', err)
		renderWithGenericError(req, res, 'app/products', {
			output: {
				products: [],
				searchTerm: searchTerm
			}
		}, 'Unable to search products.')
	})
}

module.exports.modifyProduct = function (req, res) {
	setResponseSecurityHeaders(res)

	if (!req.query.id || req.query.id == '') {
		output = {
			product: {}
		}
		setResponseSecurityHeaders(res)
		return res.render('app/modifyproduct', {
			output: output
		})
	}

	db.Product.find({
		where: {
			'id': req.query.id
		}
	}).then(product => {
			if (!product) {
				product = {}
			}
			output = {
				product: product
			}
			setResponseSecurityHeaders(res)
			res.render('app/modifyproduct', {
				output: output
			})
		}).catch(err => {
			logDatabaseError('Failed to load product for modification:', err)
			renderWithGenericError(req, res, 'app/modifyproduct', {
				output: {
					product: {}
				}
			}, 'Unable to load product details.')
		})
}

module.exports.modifyProductSubmit = function (req, res, next) {
	if (!req.body.id || req.body.id == '') {
		req.body.id = 0
	}

	db.Product.find({
		where: {
			'id': req.body.id
		}
	}).then(product => {
			if (!product) {
				product = new db.Product()
			}
			product.code = req.body.code
			product.name = req.body.name
			product.description = req.body.description
			product.tags = req.body.tags
			product.save().then(p => {
				if (p) {
					req.flash('success', 'Product added/modified!')
					return res.redirect('/app/products')
				}
			}).catch(err => {
				logDatabaseError('Failed to save product:', err)
				renderWithGenericError(req, res, 'app/modifyproduct', {
					output: {
						product: product
					}
				}, 'An error occurred while saving the product.')
			})
		}).catch(err => {
			logDatabaseError('Failed to load product for modification:', err)
			renderWithGenericError(req, res, 'app/modifyproduct', {
				output: {
					product: {}
				}
			}, 'An error occurred while saving the product.')
		})
}

module.exports.userEdit = function (req, res) {
	setResponseSecurityHeaders(res)
	res.render('app/useredit', {
		userId: req.user.id,
		userEmail: req.user.email,
		userName: req.user.name
	})
}

module.exports.userEditSubmit = function (req, res) {
	db.User.find({
		where: {
			'id': req.body.id
		} 		
	}).then(user =>{
		if(req.body.password.length>0){
			if(req.body.password.length>0){
				if (req.body.password == req.body.cpassword) {
					user.password = bCrypt.hashSync(req.body.password, bCrypt.genSaltSync(10), null)
				}else{
					req.flash('warning', 'Passwords dont match')
					setResponseSecurityHeaders(res)
					res.render('app/useredit', {
						userId: req.user.id,
						userEmail: req.user.email,
						userName: req.user.name,
					})
					return		
				}
			}else{
				req.flash('warning', 'Invalid Password')
				setResponseSecurityHeaders(res)
				res.render('app/useredit', {
					userId: req.user.id,
					userEmail: req.user.email,
					userName: req.user.name,
				})
				return
			}
		}
		user.email = req.body.email
		user.name = req.body.name
		user.save().then(function () {
			req.flash('success','Updated successfully')
			setResponseSecurityHeaders(res)
			res.render('app/useredit', {
				userId: req.body.id,
				userEmail: req.body.email,
				userName: req.body.name,
			})
		})
	})
}

module.exports.redirect = function (req, res) {
	res.status(400).send('invalid redirect url')
}

module.exports.calc = function (req, res) {
	if (req.body.eqn) {
		setResponseSecurityHeaders(res)
		res.render('app/calc', {
			output: mathjs.eval(req.body.eqn)
		})
	} else {
		setResponseSecurityHeaders(res)
		res.render('app/calc', {
			output: 'Enter a valid math string like (3+3)*2'
		})
	}
}

module.exports.listUsersAPI = function (req, res) {
	db.User.findAll({}).then(users => {
		res.status(200).json({
			success: true,
			users: users
		})
	})
}

module.exports.bulkProductsLegacy = function (req,res){
	// TODO: Deprecate this soon
	if(req.files.products){
		var products = serialize.unserialize(req.files.products.data.toString('utf8'))
		products.forEach( function (product) {
			var newProduct = new db.Product()
			newProduct.name = product.name
			newProduct.code = product.code
			newProduct.tags = product.tags
			newProduct.description = product.description
			newProduct.save()
		})
		return res.redirect('/app/products')
	}else{
		setResponseSecurityHeaders(res)
		res.render('app/bulkproducts',{messages:{danger:'Invalid file'},legacy:true})
	}
}

module.exports.bulkProducts =  function(req, res) {
	if (req.files.products && req.files.products.mimetype=='text/xml'){
		var products = libxmljs.parseXmlString(req.files.products.data.toString('utf8'), {noent:true,noblanks:true})
		products.root().childNodes().forEach( product => {
			var newProduct = new db.Product()
			newProduct.name = product.childNodes()[0].text()
			newProduct.code = product.childNodes()[1].text()
			newProduct.tags = product.childNodes()[2].text()
			newProduct.description = product.childNodes()[3].text()
			newProduct.save()
		})
		return res.redirect('/app/products')
	}else{
		setResponseSecurityHeaders(res)
		res.render('app/bulkproducts',{messages:{danger:'Invalid file'},legacy:false})
	}
}

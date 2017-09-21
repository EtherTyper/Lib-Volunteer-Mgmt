var mongoose = require('mongoose');
module.exports = new mongoose.Schema ({
	name: {
		type: String,
		required: true
	},
	fname: {
		type: String,
		required: true
	},
	lname: {
		type: String,
		required: true
	},
	approved : {
		type: Boolean,
		default: false
	},
	email: {
		type: String,
		required: true,
		match: /.+@.+\.+/,
		lowercase: true
	},
	password: {
		type: String,
		required: true
	},
	telephonenumber: {
		type: String,
		required: true
	},
	admin : {
		type: Boolean,
		default: false
	} ,
	emailValidated : {
		type: Boolean,
		default: false
	},
	graduationyear: {
		type: Number
	},
	gender: {
		type: String
	},
	age: {
		type: Number
	},
	grade: {
		type: Number
	},

	validateAccountToken: String,
	validateAccountExpires: Date,
	resetPasswordToken: String,
  resetPasswordExpires: Date
});

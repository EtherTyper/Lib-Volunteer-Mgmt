var mongoose = require('mongoose');
module.exports = new mongoose.Schema ({
	name: {
		type: String,
		required: true,
	},
	datestring: {
		type: String,
		required: true
	},
	date: {
		type: Number,
		required: true
	},
	hours: {
		type: Number,
		required: true
	},
	slot : {
		type: String,
		required: true
	} ,
	completed : {
		type: Boolean,
		default: false
	}
});

var mongoose = require('mongoose');
module.exports = new mongoose.Schema ({
	yr : {
		type: Number,
		required: true
	},
	month: {
		type: Number,
		required: true
	},
	day: {
		type: Number,
		required: true
	},
	dayofweek: {
		type: Number,
		required: true
	},
	date: {
		type: Number
	},
	hn: {
		type: Array,
		elements: {
			type: Number
		}
	},
	vn: {
		type: Array,
		elements: {
			type: Number
		}
	},
	tn: {
		type: Array,
		elements: {
			type: String
		}
	},
	dp: {
		type: Array,
		elements: {
			type: String
		}
	},
	ts: {
		type: Array,
		elements: {
			type: Array,
			elements: {
				type: String,
			}
		}
	}

});

/*
script to initialize calendar database
*/
var moment = require('moment');

var Schedule = {
    'Sunday': {
        'tn': ["11 am - 1 pm", "1 pm - 3 pm","3 pm - 5 pm"],
        'hn': [2, 2, 2],
        'vn': [9,9,9]
    },
    'Monday': {
        'tn': ["10 am - 12 pm" , "12 pm - 2 pm", "2 pm - 4 pm", "4 pm - 7 pm"],
        'hn': [2,2,2,3],
        'vn': [9,9,9,9]
    },
    'Tuesday': {
      'tn': ["10 am - 12 pm" , "12 pm - 2 pm", "2 pm - 4 pm", "4 pm - 7 pm"],
      'hn': [2,2,2,3],
      'vn': [9,9,9,9]
    },
    'Wednesday': {
      'tn': ["10 am - 12 pm" , "12 pm - 2 pm", "2 pm - 4 pm", "4 pm - 7 pm"],
      'hn': [2,2,2,3],
      'vn': [9,9,9,9]
    },
    'Thursday': {
      'tn': ["10 am - 12 pm" , "12 pm - 2 pm", "2 pm - 4 pm", "4 pm - 7 pm"],
      'hn': [2,2,2,3],
      'vn': [9,9,9,9]
    },
    'Friday': {
      'tn': ["11 am - 1 pm", "1 pm - 3 pm","3 pm - 5 pm"],
      'hn': [2, 2, 2],
      'vn': [9,9,9]
    },
    'Saturday': {
      'tn': ["11 am - 1 pm", "1 pm - 3 pm","3 pm - 5 pm"],
      'hn': [2, 2, 2],
      'vn': [9,9,9]
    }
}

//Initialize dB for a year
var current = moment("2017-03-01", "YYYY-MM-DD");
var end_date = moment("2018-02-28", "YYYY-MM-DD")

var num2day = function(num) {
    var daysofweek = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
    return (daysofweek[num]);
}

while (end_date.isSameOrAfter(current)) {

    var rec = {};

    rec['yr'] = current.get('year');
    rec['month'] = current.get('month') + 1;
    rec['day'] = current.get('date');
    rec['dp'] = [];
    var dayofweek = num2day(current.day());
    rec['tn'] = Schedule[dayofweek]['tn'];
    rec['hn'] = Schedule[dayofweek]['hn'];
    rec['vn'] = Schedule[dayofweek]['vn'];

    //These 2 are useful for repeat until functionality when
    //booking volunteer slots
    rec['dayofweek'] = current.day();
    //Following is required to get json date string to
    //import as a date in mongodb.
    //month is 0 indexed, so subtract 1
    //rec['date'] = { '$date' : new Date(rec['yr'],rec['month']-1,rec['day'],0,0,0).toISOString() } ;
    rec['date'] = Date.UTC(rec['yr'], rec['month'] - 1, rec['day']);

    var day = Schedule[dayofweek];
    var temp = [];
    for (var t = 0; t < rec['tn'].length; t++) {
        temp.push([]);
    }
    rec['ts'] = temp;

    console.log(rec);

    //increment current by 1 day , see moment documentation
    current = moment(current.add(1, 'day'));
}

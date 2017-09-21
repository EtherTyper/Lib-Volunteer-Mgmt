//-------------------------------------------------------
// Library Volunteer Management
// Node.js/Express Webserver
// Database backend : MongoDb, accessed via Mongoose node 
//                    module
// Author: Viren Velacheri (viren.velacheri@gmail.com)
//-------------------------------------------------------
// Imported Modules
//-------------------------------------------------------
var express = require('express');
var _ = require('underscore');
var path = require('path');
var favicon = require('serve-favicon');
var logger = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');

var routes = require('./routes/index');
var users = require('./routes/users');
var cons = require('consolidate');
var swig = require('swig');
var mongoose = require('mongoose');

var passport = require('passport');
var LocalStrategy = require('passport-local');
var flash = require('express-flash');

var session = require('express-session');
var expressValidator = require('express-validator');

var bcrypt = require('bcrypt-nodejs');
var async = require('async');
var crypto = require('crypto');

var nodemailer = require('nodemailer');

//SMTP login credentials
//This is a private file not in github, private-smtp-auth.js
var smtpauth = require('./private-smtp-auth');
var smtpConfig = {
    host: 'mail.smtp2go.com',
    port: 2525,
    secure: false, // upgrade later with STARTTLS
    auth: {
        user: smtpauth.user,
        pass: smtpauth.password
    }
};

var transporter = nodemailer.createTransport(smtpConfig);

//Enable APP debug messages using
//DEBUG=app nodemon bin/www.js
//For messages from all node modules
//DEBUG=* nodemon bin/www.js
var debug = require('debug');
var DLOG = debug('app');
var MIN_PASSWORD_LENGTH = 4;

//This is a private file not in github, private-mailgun-auth.js
//module.exports = {
//  api_key : '-------- your mailgun key here ------------',
//  domain : '--------- your mailgun domain here ---------'
//}
var auth = require('./private-mailgun-auth');

//Required for smtp 2 go
auth.send_domain = 'volmgmt.herokuapp.com';

var mailgun = require('mailgun-js')({
    apiKey: auth.api_key,
    domain: auth.domain,
    sender_domain: 'volmgmt'
});

var app = express();

function emailUser(input) {
    return input.split('@')[0];
}
swig.setFilter('emailUser', emailUser);
// => <p>Things!</p>

// view engine setup
app.set('views', path.join(__dirname, 'views'));
//app.set('view engine', 'jade');
app.set('view engine', 'html');
app.engine('.html', cons.swig);

// uncomment after placing your favicon in /public
//app.use(favicon(path.join(__dirname, 'public', 'favicon.ico')));
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({
    extended: false
}));
app.use(expressValidator());

app.use(cookieParser());
app.use(session({
    secret: 'skjfslkj8976329',
    resave: true,
    saveUninitialized: true
}));
app.use(flash());

app.use(passport.initialize());
app.use(passport.session());

app.use(express.static(path.join(__dirname, 'public')));

//Mongoose Schemas
var calendarSchema = require('./calendarSchema.js');

calendarSchema.methods.getDayOfWeek = function() {
    var daysofweek = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
    return (daysofweek[this.dayofweek]);
}

var userSchema = require('./userschema.js');

userSchema.pre('save', function(next) {
    var user = this;
    var SALT_FACTOR = 5;

    if (!user.isModified('password')) return next();

    bcrypt.genSalt(SALT_FACTOR, function(err, salt) {
        if (err) return next(err);

        bcrypt.hash(user.password, salt, null, function(err, hash) {
            if (err) return next(err);
            user.password = hash;
            //user.name = user.fname + '-' + user.lname ;
            next();
        });
    });
});

userSchema.methods.comparePassword = function(candidatePassword, cb) {
    bcrypt.compare(candidatePassword, this.password, function(err, isMatch) {
        if (err) return cb(err);
        cb(null, isMatch);
    });
};

var hoursSchema = require('./hoursSchema.js');

//MongoDb connection
var database = process.env.MONGOLAB_URI || 'mongodb://localhost:27017/test';
mongoose.connect(database);

// CONNECTION EVENTS
// When successfully connected
mongoose.connection.on('connected', function() {
    console.log('Mongoose default connection open to ' + database);
});

// If the connection throws an error
mongoose.connection.on('error', function(err) {
    console.log('Mongoose default connection error: ' + err);
});

// When the connection is disconnected
mongoose.connection.on('disconnected', function() {
    console.log('Mongoose default connection disconnected');
});

// If the Node process ends, close the Mongoose connection
process.on('SIGINT', function() {
    mongoose.connection.close(function() {
        console.log('Mongoose default connection disconnected through app termination');
        process.exit(0);
    });
});

//Mongoose models
var LibUser = mongoose.model('LibUser', userSchema, 'libuser');
var Cal = mongoose.model('Cal', calendarSchema, 'calendar');
var LibHour = mongoose.model('LibHour', hoursSchema, 'libhour');

//Helper functions
var dateString1 = function(yr, month, day) {
    if (month < 10) {
        var month1 = "0" + String(month);
    } else {
        month1 = String(month);
    }
    if (day < 10) {
        var day1 = "0" + String(day);
    } else {
        day1 = String(day);
    }

    return yr + "-" + month1 + "-" + day1;
};

//Return Number of seconds since 1/1/1970 UTC time
//Date format: Year/Month/Day , Month is from 1 to 12
var getUTCDate = function(yr, month, day) {
    return Date.UTC(parseInt(yr), parseInt(month) - 1, parseInt(day));
}

passport.use(new LocalStrategy({
        usernameField: 'email',
        passwordField: 'password'
    },

    function(email, password, done) {

        LibUser.findOne({
                'email': email
            },
            function(error, user) {
                if (error) {
                    return done(error);
                }
                if (!user) {
                    DLOG("User not found with email " + email);
                    return done(null, false, {
                        'message': 'User not found'
                    });
                }

                //compare password to hashed (bcrypted) version of password stored in DB
                user.comparePassword(password, function(err, isMatch) {
                    if (isMatch) {
                        if (user.approved)
                            return done(null, user);
                        else
                            return done(null, false, {
                                'message': 'Account not approved yet'
                            })
                    } else {
                        return done(null, false, {
                            'message': 'Incorrect password.'
                        });
                    }
                });
            }
        );
    }));

passport.serializeUser(function(user, done) {
    done(null, user._id);
});

passport.deserializeUser(function(id, done) {
    LibUser.findById(id, function(err, user) {
        done(err, user);
    });
});

//app.use('/', routes);
app.get('/signup', function(req, res) {
    res.render('signup.html', {
        title: 'Library Member Request'
    });
});

app.post('/signup', function(req, res, next) {

    var app_next = next;

    DLOG("in post : signup");
    DLOG("req.body.fname:" + req.body.fname);
    DLOG("req.body.lname:" + req.body.lname);
    DLOG("req.body.email:" + req.body.email);
    DLOG("req.body.telephonenumber:" + req.body.telephonenumber);
    DLOG("req.body.password:" + req.body.password);

    //Validate form input
    req.checkBody("fname", "Enter a valid first name").isAlpha();
    req.checkBody("lname", "Enter a valid last name").isAlpha();
    req.checkBody("email", "Enter a valid email").isEmail();
    req.checkBody("telephonenumber", "Enter a valid phone number").isMobilePhone('en-US');

    var errors = req.validationErrors();

    if (errors) {
        //errors is a list of objects of the form:
        //[ {param:'field_name' , msg:'error message' , value:'input value'} , { param...} ]
        req.flash('error', 'Incorrect form input');
        return res.render('signup.html', {
            errors: _.pluck(errors, 'msg')
        });
    } else {
        // normal processing here
        async.waterfall([
            function(done) { //generate random token
                //crypto is a built in node module (no need for npm install)
                crypto.randomBytes(20, function(err, buf) {
                    var token = buf.toString('hex');
                    done(err, token);
                });
            },
            function(token, done) {
                LibUser.findOne({
                    email: req.body.email
                }, function(err, user) {
                    if (user) {
                        req.flash('error', 'Account with that email address already exists. Use forgot password link if necessary');
                        return res.redirect('/');
                        //user.validateAccountToken = token;
                        //user.validateAccountExpires = Date.now() + 3600000;
                    } else {
                        user = new LibUser({
                            name: req.body.fname + ' ' + req.body.lname,
                            fname: req.body.fname,
                            lname: req.body.lname,
                            approved: false,
                            email: req.body.email,
                            password: req.body.password,
                            telephonenumber: req.body.telephonenumber,
                            gender: req.body.gender,
                            age: parseInt(req.body.age),
                            graduationyear: parseInt(req.body.graduationyear),
                            grade: parseInt(req.body.grade),
                            admin: false,
                            validateAccountToken: token,
                            validateAccountExpires: Date.now() + 3600000
                        });
                    }
                    user.save(function(err) {
                        done(err, token, user);
                    });
                });
            },
            function(token, user, done) {
                var mailOptions = {
                    to: user.email,
                    from: 'postmaster@' + auth.send_domain,
                    subject: 'Validate email for Volunteer Account',
                    text: 'In order to activate your volunteer account' +
                        ' please click on the following link, or paste this into your browser to complete the process:\n\n' +
                        'http://' + req.headers.host + '/validate/' + token + '\n\n'
                };
                //mailgun.messages().send(mailOptions, function(err, body) {
                transporter.sendMail(mailOptions, function(err, body) {
                    req.flash('info', 'An e-mail has been sent to ' + user.email + ' with further instructions.');
                    DLOG(body);
                    done(err, 'done');
                });
            }
        ], function(err) {
            if (err) return app_next(err);
            res.redirect('/login');
        });
    }
});

app.get('/validate/:token', function(req, res) {
    LibUser.findOne({
        validateAccountToken: req.params.token

        //Remove validateToken expiry check
        //Timezone differences between server and client
        //validateAccountExpires: {
        //  $gt: Date.now()
        //}

    }, function(err, user) {
        if (!user) {
            req.flash('error', 'Email validate token is invalid or has expired.');
            return res.redirect('/signup');
        }
        user.emailValidated = true;
        user.validateAccountToken = undefined;
        user.validateAccountExpires = undefined;

        user.save(function(err) {
            if (err)
                DLOG("/validate/:token error");
            else {
                res.render('account-validated-ack.html', {
                    'user': user,
                    'title': "Email Validated"
                });
            }
        });
    });
});

app.get('/', function(req, res) {
    res.render('login.html', {
        'title': 'Login'
    });
});

app.get('/usercontact', function(req, res) {
    req.session.returnTo = "/usercontact";
    res.render('contact.html', {
        admin: req.user.admin
    });
});

app.get('/admincontact', function(req, res) {
    req.session.returnTo = "/admincontact";
    res.render('contact.html', {
        admin: req.user.admin
    });
});

app.post("/postContact", function(req, res) {

    req.assert('name', 'Name cannot be blank').notEmpty();
    req.assert('email', 'Email is not valid').isEmail();
    req.assert('message', 'Message cannot be blank').notEmpty();

    var errors = req.validationErrors();

    if (errors) {
        DLOG(errors);
        //console.log("errors in form validator")
        req.flash('error', _.pluck(errors, 'msg'));
        return res.redirect(req.session.returnTo);
    }

    var from = req.body.email;
    var name = req.body.name;
    var body = req.body.message;

    var data = {
        from: 'postmaster@' + auth.send_domain,
        to: 'viren.velacheri@gmail.com',
        subject: 'Contact Form | Library Volunteer Management'
    };

    data['text'] = "Email from: " + from + " (" + name + ")\n" + body;

      //mailgun.messages().send(mailOptions, function(err, body) {
      transporter.sendMail(data, function(err, body) {
        if (err) {
            req.flash('error', err.message);
            return res.redirect(req.session.returnTo);
        }
        req.flash('success', 'Email has been sent successfully!');

        if (req.user.admin)
            return res.redirect('/adminpage');
        else
            return res.redirect('/responsivecalendar');
    });
});

var adminLog = debug('app:admin');
app.get('/adminpage', isAuthenticatedAdmin, function(req, res) {

    var year = req.query.year;
    var month = req.query.month;
    var day = req.query.day;

    if (year == undefined || month == undefined || day == undefined) {
        var today = new Date();
        year = today.getFullYear();
        month = today.getMonth() + 1;
        day = today.getDate();
    }

    adminLog("year = " + year);
    adminLog("month = " + month);
    adminLog("date = " + day);

    Cal.findOne({
        'yr': parseInt(year),
        'month': parseInt(month),
        'day': parseInt(day)
    }, function(error, calrec) {

        adminLog(JSON.stringify(calrec));

        if (error || (calrec == null)) {
            req.flash("error", "Date out of range");
            return res.redirect('back');
            adminLog(error);
        }

        var datestring = year + "/" + month + "/" + day;

        //Now find in LibHour collection
        LibHour.find({
            datestring: datestring
        }, function(err, recs) {
            if (err) {
                req.flash("error", "Can't access Lib hour database");
                return res.redirect('back');
                adminLog(error);
            }

            adminLog(JSON.stringify(recs));

            if (recs == undefined) recs = [];

            var result = {};
            result['slotname'] = [];
            result['slotinfo'] = {};
            for (var i = 0; i < calrec.tn.length; i++) {
                result['slotname'].push(calrec.tn[i]);
                result['slotinfo'][calrec.tn[i]] = _.where(recs, {
                    slot: calrec.tn[i]
                });
            } //for

            adminLog(JSON.stringify(result));

            res.render('admin.html', {
                result: result,
                dayofweek: calrec.getDayOfWeek(),
                title: 'Admin Home Page',
                year: year,
                month: month,
                date: day,
                admin: req.user.admin
            });

        });
    });
});

var arptLog = debug('app:adminreport');
app.get('/adminreports', isAuthenticatedAdmin, function(req, res) {
    res.render('admin-report.html', {
        admin: req.user.admin
    });
});

//User profile form
app.get('/userprofile', isAuthenticated, function(req, res) {
    res.render('profile.html', {
        user: req.user,
        admin: req.user.admin
    });
});

//Update telephonenumber in profile form
app.post('/updatetelephone', isAuthenticated, function(req, res) {
    req.checkBody("telephonenumber", "Enter a valid phone number").isMobilePhone('en-US');
    var errors = req.validationErrors();
    if (errors) {
        req.flash('error', 'Invalid phone number');
        return res.redirect('/userprofile');
    } else {
        LibUser.update({
            'email': req.body.email
        }, {
            $set: {
                'telephonenumber': req.body.telephonenumber
            }
        }, {
            multi: false
        }, function(err) {
            if (err) {
                DLOG("Error updating telephonenumber");
                req.flash('error', 'Unable to update telephone enumber');
                return res.redirect('back');
            }
            req.flash('info', 'Successfully updated telephone number');
            return res.redirect('/userprofile');
        });
    }
});

//Update password in profile form
app.post('/updatepassword', isAuthenticated, function(req, res) {
    LibUser.findOne({
        email: req.body.email
    }, function(err, user) {
        if (!user) {
            req.flash('error', 'Unable to find user with email ::' + req.body.email);
            return res.redirect('back');
        }

        var passwordlen = req.body.password.length;
        //Update password
        if (req.body.password == req.body.passwordagain &&
            passwordlen >= MIN_PASSWORD_LENGTH) {
            user.password = req.body.password;
            user.save(function(err) {
                if (err) {
                    DLOG("Unable to update password");
                    req.flash('error', "Unable to update password, try again");
                    return res.redirect('back');
                }
                req.flash('info', 'Successfully updated password');
                return res.redirect('/userprofile');
            });
        } else {
            if (passwordlen >= MIN_PASSWORD_LENGTH)
                req.flash('error', 'Password fields must match');
            else
                req.flash('error', 'Password  must be at least ' +
                    MIN_PASSWORD_LENGTH + ' chars long');
            return res.redirect('/userprofile');
        }
    });
});

app.get('/userreports', isAuthenticated, function(req, res) {
    res.render('user-report.html', {
        admin: req.user.admin
    });
});

//Call for autocomplete field in adminreports
//call is of the form /getusers?term="foo" , where foo is what
//the user starts typing in the autocomplete input field
app.get('/getusers', isAuthenticatedAdmin, function(req, res) {
    LibUser.find({
        name: new RegExp(req.query.term, "i")
    }, {
        name: 1,
        _id: 0
    }, function(err, recs) {
        if (err) {
            arptLog("Unable to access Lib user collection");
            res.redirect('back');
        } else {
            var users = _.pluck(recs, 'name');
            arptLog('users =' + JSON.stringify(users));
            res.json(users);
        }
    });
});

app.get('/generatereport', isAuthenticated, function(req, res) {
    var username;
    //If administrator is generating report, username
    //will come from query field and be of the form 'fname-lname'
    //else use the session field
    if (req.user.admin) {
        username = req.query.name;
    } else {
        username = req.user.name;
    }

    req.session.emailreport = null;
    LibHour.
    find({
        'date': {
            '$lte': Date.parse(req.query.end),
            '$gte': Date.parse(req.query.start)
        },
        'name': username,
        'completed': true
    }).
    sort({
        date: 1
    }).
    exec(function(err, recs) {
        if (err) {
            DLOG('generatereport:: LibHour query not successful');
            res.redirect('back');
        } else {
            DLOG(JSON.stringify(recs));
            var hours = _.pluck(recs, 'hours');
            var totalhours = _.reduce(hours, function(memo, num) {
                return memo + num;
            }, 0);

            var emailreport = {};
            emailreport['totalhours'] = totalhours;
            emailreport['user'] = username;
            emailreport['entry'] = [];
            emailreport['start'] = req.query.start;
            emailreport['end'] = req.query.end;
            recs.forEach(function(rec) {
                emailreport['entry'].push(rec.datestring + "::" + rec.slot + "::" + rec.hours);
            });
            req.session.emailreport = emailreport;

            res.render('report-output.html', {
                result: recs,
                totalhours: totalhours,
                user: username,
                start: req.query.start,
                end: req.query.end,
                admin: req.user.admin
            });
        }
    });
});

//Email
app.get('/emailreport', function(req, res) {

    if (req.query.emailto == "") {
        req.flash("error", "No email for report specified");
        return res.redirect('/adminreports');
    }

    var emailreport = req.session.emailreport;
    if (emailreport == null) {
        req.flash('error', "Null user report, not emailing");
        return res.redirect('back');
    }

    var tofield = req.query.emailto ;
    var subject = 'Volunteer Hour report for ' + emailreport['user'] + "::" +
        emailreport['start'] + ' to ' + emailreport['end'];
    var emailtext ;
    if (emailreport['totalhours'] == 0)
      emailtext = subject + '\n\nTotal hours = ' + emailreport['totalhours'];
    else {
      emailtext = subject + '\n\n' + emailreport['entry'].join('\n\n') + '\n\n Total hours = ' + emailreport['totalhours'];
    }
    var mailOptions = {
        to: tofield,
        from: 'postmaster@' + auth.send_domain,
        //ToDo for now only 1 day
        subject: subject,
        text: emailtext
    };

      //mailgun.messages().send(mailOptions, function(err, body) {
      transporter.sendMail(mailOptions, function(err, body) {
        if (err) {
            dlsLog('mailgun returned error');
            req.flash("error", "[Mail error]::Unable to send email");
            return res.redirect('back');
        } else {
            req.flash("info", "Successfully sent report email");
            if (req.user.admin)
              return res.redirect('/adminreports');
            else {
              return res.redirect('/responsivecalendar');
            }
        }
    });
});

var cfhLog = debug('app:confirmhours');
app.get('/confirmhours', isAuthenticatedAdmin, function(req, res) {
    var query = {
        datestring: req.query.datestring,
        name: req.query.name,
        slot: req.query.slot
    };
    cfhLog(query);
    LibHour.update(query, {
        $set: {
            'completed': req.query.confirm == 'yes'
        }
    }, {
        multi: false
    }, function(error, status) {
        if (error) {
            cfhLog(error);
        } else {
            cfhLog("Successful update :" + JSON.stringify(status));
            setTimeout(function() {
                    res.json({
                        status: status
                    });
                },
                1000);
        }
    });
});

app.get('/listusers', isAuthenticatedAdmin, function(req, res) {
    //Find all users, then groupby approved flag being true or
    //false
    LibUser.find({
            emailValidated: true
        },
        function(error, recs) {
            recs.forEach( function(rec){
              if (rec.admin)
                rec['access'] = 'admin';
              else
                rec['access'] = 'user';
            });
            var users = {};

            //Split into approved and not-approved groups
            users['approved'] = _.where(recs, {
                'approved': true
            });
            users['not-approved'] = _.where(recs, {
                'approved': false
            });

            //Sort each group
            users['approved'] = _.sortBy(users['approved'], 'name');
            users['not-approved'] = _.sortBy(users['not-approved'], 'name');

            res.render('admin-users.html', {
                results: users,
                'title': 'Admin::List users',
                admin: req.user.admin
            });
        });
});

app.get('/getusrdetails/:id', isAuthenticatedAdmin, function(req, res) {
    LibUser.findOne({
        '_id': req.params.id
    }, function(error, user) {
        DLOG(JSON.stringify(user));
        res.render('userdetails.html', {
            user: user,
            title: 'User Details',
            admin: req.user.admin
        });
    });
});

app.get('/getprocess_approval/:id', isAuthenticatedAdmin, function(req, res) {
    var approved_flag = (req.query.approve == 'yes');

    LibUser.update({
        '_id': req.params.id
    }, {
        $set: {
            'approved': approved_flag
        }
    }, {
        multi: false
    }, function(err) {
        if (err) {
            DLOG(error);
            req.flash("error", "Error updating libuser record with approval");
            return res.redirect('back');
        } else {
            LibUser.findOne({
                '_id': req.params.id
            }, function(err, rec) {
                if (err) {
                    DLOG(err);
                    req.flash("error", "Error locating libuser record with id:" + req.params.id);
                    return res.redirect('back');
                } else {
                    var email_text;
                    if (approved_flag) {
                        email_text = rec.name + ' has been approved as a volunteer.\n You can now signup for volunteer slots.'
                    } else {
                        email_text = rec.name + ' has not been approved as a volunteer.\n Please contact the library.'
                    }

                    var mailOptions = {
                        to: rec.email,
                        from: 'postmaster@' + auth.send_domain,
                        //ToDo for now only 1 day
                        subject: 'Volunteer Approval Request for ' + rec.name,
                        text: email_text
                    };
                      //mailgun.messages().send(mailOptions, function(err, body) {
                      transporter.sendMail(mailOptions, function(err, body) {
                        if (err) {
                            DLOG('mailgun returned error');
                            req.flash("error", "[mailgun error]::sending email after volunteer approval request");
                            return res.redirect('back');
                        }
                        req.flash('info', 'An e-mail has been sent to ' + rec.email + ' regarding their volunteer request');
                        DLOG(body);
                        return res.redirect('/listusers');
                    });
                }
            });
        }
    });
});

//Decide later on whether people not approved should be deleted
// app.get('/getprocess_disapproval/:id', isAuthenticatedAdmin, function(req, res) {
//     LibUser.remove({
//         '_id': req.params.id
//     }, function(error) {
//         if (error) {
//             DLOG(error);
//         }
//     });
//     res.render('approval.html');
// });

app.get('/login', function(req, res) {
    res.render('login.html', {
        title: 'Login page',
        nxt: req.query.nxt
    });
});

function isAuthenticated(req, res, next) {
    DLOG("req.user = " + req.user);
    if (req.isAuthenticated())
        next();
    else {
        DLOG("Unauthorized acess: Not logged in");
        req.flash('info', 'Please log in for access');
        var newUrl = '/login?nxt=' + encodeURIComponent(req.originalUrl);
        DLOG(newUrl);
        res.redirect(newUrl);
    }
}

function isAuthenticatedAdmin(req, res, next) {
    DLOG("req.user = " + req.user);
    if (req.isAuthenticated() && req.user.admin)
        next();
    else {
        DLOG("Unauthorized acess: Admin only");
        req.flash("error", "Unauthorized acess: Admin only");
        res.render('login.html', {
            title: 'Volmgmt Login'
        });
    }
}

app.post('/login', passport.authenticate('local', {
    //    successRedirect: '/responsivecalendar',
    failureRedirect: '/login',
    failureFlash: true
}), function(req, res) {

    //If user has admin priviledges go to admin page
    if (req.user.admin) {
        res.redirect('/adminpage');
    } else {
        //Handle case where someone is not logged in and clicks
        //on a link to go to the libraryschedule page directly
        DLOG(decodeURIComponent(req.body.nxt));
        if (req.body.nxt.indexOf('libraryschedule') != -1)
            res.redirect(decodeURIComponent(req.body.nxt));
        else
            res.redirect('/responsivecalendar');
    }
});

app.get("/adminlogin", function(req, res) {
    res.render('adminlogin.html', {
        title: 'Admin login',
        admin: req.user.admin
    });
});

app.post('/process_adminlogin', passport.authenticate('local', {
    successRedirect: "/adminpage",
    failureRedirect: "/adminlogin",
    failureFlash: true
}));

app.get('/logout', function(req, res) {
    req.logout();
    res.redirect('/login');
});

app.get('/libraryschedule', isAuthenticated, function(req, res) {
    Cal.findOne({
        'yr': parseInt(req.query.year),
        'month': parseInt(req.query.month),
        'day': parseInt(req.query.day)
    }, function(error, rec) {

        DLOG(JSON.stringify(rec));

        if (error || (rec == null)) {
            req.flash("error", "Date out of range");
            return res.redirect('back');
            DLOG(error);
        }

        var enable = [];
        for (var i = 0; i < rec.ts.length; i++) {
            if (rec.ts[i].length < rec.vn[i])
                enable[i] = true;
            else
                enable[i] = false;
        }
        DLOG(JSON.stringify(rec));
        DLOG(JSON.stringify(enable))
        res.render('library_schedule_form.html', {
            result: rec,
            dayofweek: rec.getDayOfWeek(),
            status: enable,
            admin: req.user.admin
        });
    });
});

app.get('/responsivecalendar', isAuthenticated, function(req, res) {
    req.session.returnTo = req.originalUrl;
    DLOG('req.user.admin = ' + req.user.admin);
    res.render('calendar.html', {
        'month': req.query.month,
        'year': req.query.year,
        'admin': req.user.admin
    });
});

app.get('/process_libraryschedule', function(req, res) {
    var query;
    DLOG("in post : process_libraryschedule");
    DLOG("req.query.year:" + req.query.year);
    DLOG("req.query.month:" + req.query.month);
    DLOG("req.query.day:" + req.query.day);
    DLOG("req.query.ts:" + req.query.ts);
    DLOG("req.query.enddate:" + req.query.enddate);
    DLOG("req.query.username:" + req.query.username);

    //Add query parameters so that we go back to month currently being displayer
    var calendar_url = '/responsivecalendar?month=' + req.query.month + '&year=' + req.query.year;

    var username;
    //If undefined, must be user login
    if (req.query.username == undefined) {
        username = req.user.name;
    }
    //when admin submits this form, they must fill in a user name
    else if (req.query.username.length > 0) {
        username = req.query.username;
    } else {
        req.flash("error", "Must select user for schedule update");
        return res.redirect(calendar_url);
    }

    DLOG('username:' + username);

    //Parse the datestring, if it is valid will return the number of milliseconds
    //since 1/1/1970 else will return NaN.
    //Use this to test for a valid date
    var enddate_ms = Date.parse(req.query.enddate);
    var valid_enddate = !isNaN(enddate_ms);

    var selectday = getUTCDate(req.query.year, req.query.month, req.query.day);

    //If user has filled out the enddate field
    if (valid_enddate) {
        enddate = enddate_ms;
    } else {
        enddate = selectday;
    }

    var dayofweek = (new Date(selectday)).getUTCDay();
    var tslots = req.query.ts;

    if (tslots) {
        DLOG('username:' + username);

        //Query from current date to enddate, for the same day of the week
        query = {
            'date': {
                '$lte': enddate,
                '$gte': selectday
            },
            'dayofweek': dayofweek
        };

        DLOG(query);

        Cal.find(query, function(err, recs) {
            if (err) {
                DLOG(err);
                req.flash("error", "[find query failed]::Unable to update schedule");
                return res.redirect('back');
            }
            //DLOG(JSON.stringify(recs));
            var status = [];
            var hours = 0;

            async.each(recs, function(rec, cbk) {

                tslots.forEach(function(slot) {
                    var updateidx = parseInt(slot);
                    //book_slot only if:
                    // 1. There are free spots available
                    // 2. User has NOT already signed up for that day
                    var slot_avail = (rec.ts[updateidx].length < rec.vn[updateidx]);

                    //This checks against a specific slot
                    var already_signedup = (_.contains(rec.ts[updateidx], username));
                    //This checks for a signup in *any* slot that day
                    //var already_signedup = (_.contains(rec.dp, username));

                    if (slot_avail && !already_signedup) {
                        status.push({
                            datestring: rec.yr + '/' + rec.month + '/' + rec.day,
                            date: getUTCDate(rec.yr, rec.month, rec.day),
                            name: username,
                            completed: false,
                            slot: rec.tn[updateidx],
                            signup: 'yes',
                            hours: rec.hn[updateidx]
                        });

                        hours = hours + rec.hn[updateidx];

                        rec.ts[updateidx].push(username);

                        //Push only if not already in dp
                        if (!_.contains(rec.dp, username))
                            rec.dp.push(username);

                    } //if (slot_avail)
                    else {
                        if (already_signedup) message = "already signed up";
                        else if (!slot_avail) message = "slot full";
                        status.push({
                            datestring: rec.yr + '/' + rec.month + '/' + rec.day,
                            slot: rec.tn[updateidx],
                            signup: message
                        });
                    }
                });

                Cal.update({
                    date: rec.date
                }, {
                    '$set': {
                        'ts': rec.ts,
                        'dp': rec.dp
                    }
                }, function(err) {
                    if (err)
                        cbk(err);
                    else {
                        DLOG("updated db record for day " + rec.day);
                        cbk(null);
                    }
                });
            }, function(err) {
                if (err) {
                    DLOG('async each returned error');
                    req.flash("error", "[async fail]::Unable to update schedule");
                    return res.redirect('back');
                } else {
                    DLOG("Hours signed up for = " + hours);
                    DLOG(status);
                    //Filter array items in status by signup='yes'
                    var status_success = _.filter(status, function(s) {
                        return s.signup == 'yes';
                    });

                    //store in LibHour collection
                    //Have to do it one record at a time, there  is no bulk insert in mongoose
                    //although bulk insert is supported in mongodb
                    async.each(status_success, function(hrec, cbk_hrec) {
                        var libhour_rec = new LibHour(hrec);

                        libhour_rec.save(function(err) {
                            if (err)
                                cbk_hrec(err);
                            else
                                cbk_hrec(null);
                        });

                    }, function(err) {
                        if (err) {
                            DLOG('libhour async each returned error');
                            req.flash("error", "[libhour async fail]::Unable to save hours");
                            return res.redirect('back');
                        }
                        //Display confirmation page/modal
                        return res.render('schedule_confirm.html', {
                            status: status,
                            year: req.query.year,
                            month: req.query.month,
                            name: username,
                            hours: hours
                        });
                    });
                }
            });
        });
    } else
        return res.redirect(calendar_url);
});

var dlsLog = debug('app:delete_libraryschedule');
app.get('/delete_libraryschedule', function(req, res) {
    var query;
    dlsLog("in post : delete_libraryschedule");
    dlsLog("req.query.year:" + req.query.year);
    dlsLog("req.query.month:" + req.query.month);
    dlsLog("req.query.day:" + req.query.day);
    dlsLog("req.query.ts:" + req.query.ts);
    dlsLog("req.query.enddate:" + req.query.enddate);
    dlsLog("req.query.username:" + req.query.username);
    dlsLog("req.query.emailenable:" + req.query.emailenable);

    //Add query parameters so that we go back to month currently being displayer
    var calendar_url = '/responsivecalendar?month=' + req.query.month + '&year=' + req.query.year;

    var username;
    //If undefined, must be user login
    if (req.query.username == undefined) {
        username = req.user.name;
    }
    //when admin submits this form, they must fill in a user name
    else if (req.query.username.length > 0) {
        username = req.query.username;
    } else {
        req.flash("error", "Must select user for schedule update");
        return res.redirect(calendar_url);
    }

    //Parse the datestring, if it is valid will return the number of milliseconds
    //since 1/1/1970 else will return NaN.
    //Use this to test for a valid date
    var enddate_ms = Date.parse(req.query.enddate);
    var valid_enddate = !isNaN(enddate_ms);

    var selectday = getUTCDate(req.query.year, req.query.month, req.query.day);

    //If user has filled out the enddate field
    if (valid_enddate) {
        enddate = enddate_ms;
    } else {
        enddate = selectday;
    }

    var dayofweek = (new Date(selectday)).getUTCDay();
    var user = username;

    var tslots = req.query.ts;

    if (tslots) {
        DLOG('username:' + username);

        //Query from current date to enddate, for the same day of the week
        query = {
            'date': {
                '$lte': enddate,
                '$gte': selectday
            },
            'dayofweek': dayofweek
        };

        dlsLog(query);

        Cal.find(query, function(err, recs) {
            if (err) {
                dlsLog(err);
                req.flash("error", "[find query failed]::Unable to delete schedule");
                return res.redirect('back');
            }
            //dlsLog(JSON.stringify(recs));
            var status = [];
            var hours = 0;

            async.each(recs, function(rec, cbk) {

                tslots.forEach(function(slot) {

                    var updateidx = parseInt(slot);

                    //This checks against a specific slot
                    var already_signedup = (_.contains(rec.ts[updateidx], username));
                    //This checks for a signup in *any* slot that day
                    //var already_signedup = (_.contains(rec.dp, username));

                    if (already_signedup) {
                        var idx;

                        if (_.contains(rec.ts[updateidx], user)) {
                            var sel = rec.ts[updateidx].indexOf(user);
                            rec.ts[updateidx].splice(sel, 1);
                            idx = updateidx;
                        }

                        /* This will delete user from all slots
                          for (var i = 0; i < rec.ts.length; i++) {
                              if (_.contains(rec.ts[i], user)) {
                                  var sel = rec.ts[i].indexOf(user);
                                  rec.ts[i].splice(sel, 1);
                                  idx = i;
                              }
                          }
                          */
                        //Is user signed up for other slots
                        var slot_count = 0;
                        for (var i = 0; i < rec.ts.length; i++) {
                            if (_.contains(rec.ts[i], user))
                                slot_count++;
                        }
                        //Remove user from dp array if slot_count is 0
                        if (slot_count == 0) {
                            if (_.contains(rec.dp, user)) {
                                var sel = rec.dp.indexOf(user);
                                rec.dp.splice(sel, 1);
                            }
                        }
                        dlsLog('rec.dp = ' + rec.dp);

                        status.push({
                            year: rec.yr,
                            month: rec.month,
                            day: rec.day,
                            datestring: rec.yr + '/' + rec.month + '/' + rec.day,
                            date: getUTCDate(rec.yr, rec.month, rec.day),
                            name: username,
                            completed: false,
                            slot: rec.tn[idx],
                            delete: 'yes',
                            hours: rec.hn[idx]
                        });

                        hours = hours + rec.hn[idx];
                    } else {
                        message = "not signed up for slot";
                        status.push({
                            datestring: rec.yr + '/' + rec.month + '/' + rec.day,
                            delete: message
                        });
                    }
                });

                Cal.update({
                    date: rec.date
                }, {
                    '$set': {
                        'ts': rec.ts,
                        'dp': rec.dp
                    }
                }, function(err) {
                    if (err)
                        cbk(err);
                    else {
                        dlsLog("updated db record for day " + rec.day);
                        cbk(null);
                    }
                });

            }, function(err) {
                if (err) {
                    dlsLog('async each returned error');
                    req.flash("error", "[async fail]::Unable to update schedule");
                    return res.redirect('back');
                } else {
                    dlsLog("Hours deleted  = " + hours);
                    dlsLog(status);
                    //Filter array items in status by signup='yes'
                    var status_success = _.filter(status, function(s) {
                        return s.delete == 'yes';
                    });

                    //Not signed up for any slot that was deleted
                    if (status_success.length == 0)
                        return res.render('delete_confirm.html', {
                            status: status,
                            year: req.query.year,
                            month: req.query.month,
                            name: username,
                            hours: hours
                        });

                    //store in LibHour collection
                    //Have to do it one record at a time, there  is no bulk insert in mongoose
                    //although bulk insert is supported in mongodb
                    async.each(status_success, function(hrec, cbk_hrec) {
                        LibHour.remove({
                            date: hrec.date,
                            name: hrec.name
                        }, function(err) {
                            if (err)
                                cbk_hrec(err);
                            else
                                cbk_hrec(null);
                        });

                    }, function(err) {
                        if (err) {
                            dlsLog('libhour async each returned error');
                            req.flash("error", "[libhour async fail]::Unable to delete hours");
                            return res.redirect('back');
                        }

                        if (req.query.emailenable == 'yes') {
                            //Send out mail to all approved users & parents
                            LibUser.find({
                                approved: true,
                                admin: false
                            }, function(err, users) {
                                if (err) {
                                    dlsLog('LibUser find returned error');
                                    req.flash("error", "[libuser find db call fail]");
                                    return res.redirect('back');
                                }
                                var email_list = _.pluck(users, 'email').join(',');
                                var datestring = status[0].datestring;
                                var year = status[0].year;
                                var month = status[0].month;
                                var day = status[0].day;

                                var mailOptions = {
                                    to: email_list,
                                    from: 'postmaster@' + auth.send_domain,
                                    //ToDo for now only 1 day
                                    subject: 'Looking for Volunteer on:' + datestring,
                                    text: 'I am unable to fulfill my volunteer commitment for ' + datestring + '.\n\n' +
                                        'If someone else can take my place. Please click on the following link, or paste this into your browser to complete the process:\n\n' +
                                        'http://' + req.headers.host + '/libraryschedule?year=' + year + '&month=' + month + '&day=' + day + '\n\n'
                                };
                                  //mailgun.messages().send(mailOptions, function(err, body) {
                                  transporter.sendMail(mailOptions, function(err, body) {
                                    if (err) {
                                        dlsLog('mailgun returned error');
                                        req.flash("error", "[mailgun error]::sending email after delete schedule");
                                        return res.redirect('back');
                                    }
                                    req.flash('info', 'An e-mail has been sent to the group requesting coverage.');
                                    DLOG(body);
                                    //Display confirmation page/modal
                                    return res.render('delete_confirm.html', {
                                        status: status,
                                        year: req.query.year,
                                        month: req.query.month,
                                        name: username,
                                        hours: hours
                                    });
                                });
                            });
                        } //if (req.query.email == 'yes')
                        else {
                          //Display confirmation page/modal
                          return res.render('delete_confirm.html', {
                              status: status,
                              year: req.query.year,
                              month: req.query.month,
                              name: username,
                              hours: hours
                          });
                        }
                    });
                }
            });
        });
    } else {
        req.flash('error', 'Select slot to delete ');
        var url = '/libraryschedule?year=' + req.query.year + '&month=' + req.query.month;
        res.redirect(url);
    }
});

// AJAX request /getcalendar_data?month=12&year=2016
app.get('/getcalendar_data', isAuthenticated, function(req, res) {
    var month = req.query.month;
    var year = req.query.year;
    var user = req.query.user;

    DLOG("month = " + month);
    DLOG("year = " + year);
    DLOG('user =' + user);

    //Query mongo db to retrieve all events matching month and year
    var query = {
        'yr': year,
        'month': month
    };

    //Return all the days in a  month
    Cal.find(query, function(err, days) {
        if (!err) {
            var result = {};

            for (var i = 0; i < days.length; i++) {
                var key = dateString1(days[i]['yr'], days[i]['month'], days[i]['day']);
                //DLOG(key);
                var day_full;
                var num_vols = 0; //count number of volunteers for that day
                var num_slots = 0; //count number of volunteer slots for that day
                for (var t = 0; t < days[i]['ts'].length; t++) {
                    num_vols = num_vols + days[i]['ts'][t].length;
                    num_slots = num_slots + days[i]['vn'][t];
                } //for
                day_full = num_vols >= num_slots;

                if (day_full)
                    result[key] = {
                        'class': 'full',
                        'number': num_vols
                    };
                //Slight difference in coloring the slot for admin vs
                //user view
                //For admin: Color Red if day full
                //For user: Color Red only if day full && user hasn't
                //          signed up that day
                //          So the logic below for a regular user will
                //          override the class full setting above
                //req.user is session variable holding all user properties
                if (req.user.admin) {
                    if (num_vols && !day_full)
                        result[key] = {
                            'class': 'active',
                            'number': num_vols
                        };
                } else {
                    if (_.contains(days[i]['dp'], req.user.name))
                        result[key] = {
                            'class': 'active',
                            'number': num_vols
                        };
                }
            } //for
            res.json(result);
        }
    });
});

app.use('/users', users);

app.get('/forgot', function(req, res) {
    res.render('forgot', {
        title: 'Forgot Password'
    });
});

app.post('/forgot', function(req, res, next) {
    async.waterfall([
        function(done) {
            crypto.randomBytes(20, function(err, buf) {
                var token = buf.toString('hex');
                done(err, token);
            });
        },
        function(token, done) {
            LibUser.findOne({
                email: req.body.email
            }, function(err, user) {
                if (!user) {
                    req.flash('error', 'No account with that email address exists.');
                    return res.redirect('/forgot');
                }

                user.resetPasswordToken = token;
                user.resetPasswordExpires = Date.now() + 3600000; // 1 hour

                user.save(function(err) {
                    done(err, token, user);
                });
            });
        },
        function(token, user, done) {
            var mailOptions = {
                to: user.email,
                from: 'postmaster@' + auth.send_domain,
                subject: 'Austin Library Volunteers: Password Reset',
                text: 'You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n' +
                    'Please click on the following link, or paste this into your browser to complete the process:\n\n' +
                    'http://' + req.headers.host + '/reset/' + token + '\n\n' +
                    'If you did not request this, please ignore this email and your password will remain unchanged.\n'
            };
              //mailgun.messages().send(mailOptions, function(err, body) {
              transporter.sendMail(mailOptions, function(err, body) {
                req.flash('info', 'An e-mail has been sent to ' + user.email + ' with further instructions.');
                DLOG(body);
                done(err, 'done');
            });
        }
    ], function(err) {
        if (err) return next(err);
        return res.redirect('/login');
    });
});

app.get('/reset/:token', function(req, res) {
    console.log('GET:/reset: ' + req.params.token);
    LibUser.findOne({
        resetPasswordToken: req.params.token
        //Forget about token expiring
        //resetPasswordExpires: {
        //  $gt: Date.now()
        //}
    }, function(err, user) {
        if (!user) {
            req.flash('error', 'Password reset token is invalid or has expired.');
            return res.redirect('/forgot');
        }
        res.render('reset', {
            user: req.user,
            title: 'Reset Password'
        });
    });
});

app.post('/reset/:token', function(req, res) {
    console.log('POST:/reset: ' + req.params.token);
    var passwd_len = req.body.password.length;
    if (passwd_len < MIN_PASSWORD_LENGTH ||
        req.body.password != req.body.confirm) {
        req.flash('error', "Passwords don't match or less than " + MIN_PASSWORD_LENGTH + " chars long");
        return res.redirect('back');
    } else {

      LibUser.findOne({resetPasswordToken: req.params.token})
      .then( (user) => {
        if (!user) {
            req.flash('error', 'Password reset token is invalid or has expired.');
            return res.redirect('/forgot');
        }

        req.flash('info', 'Password for ' + user.email + ' changed.');

        user.password = req.body.password;
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;
        return user.save();
      })
      .then( (user) => {
        var mailOptions = {
            to: user.email,
            from: 'postmaster@' + auth.send_domain,
            subject: 'Austin Library Volunteers: Your password has been changed',
            text: 'Hello,\n\n' +
                'This is a confirmation that the password for your account ' + user.email + ' has just been changed.\n'
        };

          return transporter.sendMail(mailOptions);
      })
      .then( () => {
        return res.redirect('/login');
      })
      .catch( (err) => {
        return res.redirect('/login');
      });
  }
});

// catch 404 and forward to error handler
app.use(function(req, res, next) {
    var err = new Error('Not Found');
    err.status = 404;
    next(err);
});

// error handlers

// development error handler
// will print stacktrace
if (app.get('env') === 'development') {
    app.use(function(err, req, res, next) {
        res.status(err.status || 500);
        res.render('error', {
            message: err.message,
            error: err
        });
    });
}

// production error handler
// no stacktraces leaked to user
app.use(function(err, req, res, next) {
    res.status(err.status || 500);
    res.render('error', {
        message: err.message,
        error: {}
    });
});

module.exports = app;

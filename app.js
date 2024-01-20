var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');
var mysql = require('mysql');
var session = require('express-session');


var indexRouter = require('./routes/index');
var usersRouter = require('./routes/users');

var dbConnectionPool = mysql.createPool({
    host: 'localhost',
    database: 'attackflow'
});

var app = express();

app.use(function(req, res, next){
    req.pool = dbConnectionPool;
    next();
});


app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
    secret: 'a string of your choice',
    resave: false,
    saveUninitialized: true,
    cookie: {secure: false},
    userID: -1
}));

app.use('/', indexRouter);
app.use('/users', usersRouter);

module.exports = app;
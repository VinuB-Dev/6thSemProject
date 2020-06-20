const createError = require('http-errors');
const express = require('express');
const cookieParser = require('cookie-parser');
const logger = require('morgan');
const redis = require("redis");
const cors = require('cors');
const apiRouter = require('./routes/api');

// creating db object and connecting to redis
const db = redis.createClient();
db.on('connect', function () {
    console.log("Connection to database established.")
});

// creating express app
const app = express();

// creating API router
const router = express.Router();

// adding middleware
// noinspection JSCheckFunctionSignatures
app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cors())
// noinspection JSCheckFunctionSignatures
app.use(cookieParser());

// adding routes
app.use('/api', apiRouter(db, router));

// catch 404 and forward to error handler
app.use(function(req, res, next) {
    next(createError(404));
});

// error handler
app.use(function(err, req, res) {
    // set locals, only providing error in development
    res.locals.message = err.message;
    res.locals.error = req.app.get('env') === 'development' ? err : {};

    // render the error page
    res.status(err.status || 500);
    res.json({
        message: res.locals.message,
        error: res.locals.error,
        stack: err.stack
    });
});

module.exports = app;

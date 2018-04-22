"use strict";

import * as express from "express";
import * as path from "path";
import * as cookieParser from "cookie-parser";
import * as bodyParser from "body-parser";
import * as logger from "morgan";

import IndexRoute from "./routes/index-route";

export default class Server
{
	public express : express.Application;

	private constructor()
	{
		console.log("Initializing server");
		this.express = express();
		this.configure();
	}

	private configure() : void
	{
		this.express.set("views", path.join(__dirname, "views"));
		this.express.set("view engine", "hbs");

		this.express.use(logger("dev"));
		this.express.use(bodyParser.json());
		this.express.use(bodyParser.urlencoded({ extended: false }));
		this.express.use(cookieParser());

		this.express.use("/", new IndexRoute().getRouter());
		this.express.use(express.static(path.join(__dirname, "public")));
		//this.express.use(this.fallbackHandler);
	}

	private fallbackHandler(request : express.Request, response : express.Response, next : express.NextFunction) : void
	{
		var error : HTTPError = new HTTPError("Not Found");
		error.status = 404;
		next(error);
	}

	public static create() : Server
	{
		return new Server();
	}
}

class HTTPError extends Error
{
	public status : number;
}

/*var express = require('express');
var path = require('path');
var favicon = require('serve-favicon');
var logger = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');

var index = require('./routes/index');
var users = require('./routes/users');

var app = express();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'hbs');

// uncomment after placing your favicon in /public
//app.use(favicon(path.join(__dirname, 'public', 'favicon.ico')));
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.use('/', index);
app.use('/users', users);

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  var err = new Error('Not Found');
  err.status = 404;
  next(err);
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

module.exports = app;*/
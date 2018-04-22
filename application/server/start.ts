#!/usr/bin/env node

import * as http from "http";
import * as logger from "morgan";

import Server from "./server";

class ServerStarter
{
	private server : Server;
	private httpServer : http.Server;
	private port : string;

	private constructor()
	{
		this.server = Server.create();
		this.port = process.env.PORT || "8080"; // TODO: port normalization and configuration

		this.server.express.set("port", this.port);

		this.httpServer = http.createServer(this.server.express);
		this.httpServer.on("listening", () => this.onListening(this));
		this.httpServer.on("error", (error) => this.onError(this, error));
	}

	private start() : void
	{
		this.httpServer.listen(this.port); 
	}

	private onListening(starter : ServerStarter) : void
	{
		var bind : HTTPBind = starter.httpServer.address();
		console.log("Listening on " + bind.address + ":" + bind.port);
		//console.log(this);
		//console.log("Listening on " + this.address);
	}

	private onError(starter : ServerStarter, error : Error) : void
	{
		throw error;
	}

	public static start() : void
	{
		var starter : ServerStarter = new ServerStarter();

		starter.start();
	}
}

class HTTPBind
{
	public port : number;
	public family : string;
	public address : string;
}

ServerStarter.start();

/*// Module dependencies.
var app = require('./app').bootstrap();
var debug = require('debug')('playground:server');
var http = require('http');

// Get port from environment and store in Express.
var port = normalizePort(process.env.PORT || '8080');
app.set('port', port);

// Create HTTP server.
var server = http.createServer(app);

// Listen on provided port, on all network interfaces.
server.listen(port);
server.on('error', onError);
server.on('listening', onListening);

// Normalize a port into a number, string, or false.
function normalizePort(val) {
  var port = parseInt(val, 10);

  if (isNaN(port)) {
    // named pipe
    return val;
  }

  if (port >= 0) {
    // port number
    return port;
  }

  return false;
}

// Event listener for HTTP server "error" event.
function onError(error) {
  if (error.syscall !== 'listen') {
    throw error;
  }

  var bind = typeof port === 'string'
    ? 'Pipe ' + port
    : 'Port ' + port;

  // handle specific listen errors with friendly messages
  switch (error.code) {
    case 'EACCES':
      console.error(bind + ' requires elevated privileges');
      process.exit(1);
      break;
    case 'EADDRINUSE':
      console.error(bind + ' is already in use');
      process.exit(1);
      break;
    default:
      throw error;
  }
}

// Event listener for HTTP server "listening" event.
function onListening() {
  var addr = server.address();
  var bind = typeof addr === 'string'
    ? 'pipe ' + addr
    : 'port ' + addr.port;
  debug('Listening on ' + bind);
}*/
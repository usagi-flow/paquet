#!/usr/bin/env node

import * as http from "http";
import * as Net from "net";
import * as Path from "path";
import * as logger from "morgan";

import Server from "./server";

class ServerStarter
{
	private server : Server;
	private httpServer : http.Server;
	private port : string;

	private auxiliaryServer : Server;
	private ipcServer : Net.Server;
	private pipe : string;

	private constructor()
	{
		// Prepare the primary server instance
		this.server = Server.create();
		this.port = process.env.PORT || "8080"; // TODO: port normalization and configuration

		this.server.express.set("port", this.port);

		// Prepare the auxiliary server instance
		this.auxiliaryServer = Server.create();
		this.pipe = Path.join('\\\\?\\pipe', process.cwd(), "paquet-ipc"); // TODO: magic
		console.log("Will open pipe: " + this.pipe);

		//this.auxiliaryServer.express.set("port", this.pipe);

		// Create the HTTP server using the primary server instance
		this.httpServer = http.createServer(this.server.express);
		this.httpServer.on("listening", () => this.onListening(this, this.httpServer));
		this.httpServer.on("error", (error) => this.onError(this, this.httpServer, error));

		// Create the IPC server using the auxiliary server instance
		this.ipcServer = Net.createServer();
		//this.ipcServer = http.createServer(this.auxiliaryServer.express);
		this.ipcServer.on("listening", () => this.onRawServerListening(this, this.ipcServer));
		this.ipcServer.on("error", (error) => this.onRawServerError(this, this.ipcServer, error));
	}

	private start() : void
	{
		this.httpServer.listen(this.port);
		this.ipcServer.listen(this.pipe);
	}

	private onListening(starter : ServerStarter, appServer : http.Server) : void
	{
		var bind : HTTPBind = appServer.address();
		console.log("Listening on " + bind.address + ":" + bind.port);
	}

	private onError(starter : ServerStarter, appServer : http.Server, error : Error) : void
	{
		throw error;
	}

	private onRawServerListening(starter : ServerStarter, appServer : Net.Server) : void
	{
		var bind : HTTPBind = appServer.address();
		console.log("Listening on " + bind.address + ":" + bind.port);
	}

	private onRawServerError(starter : ServerStarter, appServer : Net.Server, error : Error) : void
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
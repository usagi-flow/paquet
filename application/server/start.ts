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
		if (process.platform === "win32")
			this.pipe = Path.join('\\\\?\\pipe', process.cwd(), "paquet-ipc"); // TODO: magic
		else
			this.pipe = Path.join(process.cwd(), "paquet-ipc"); // TODO: magic
		console.log("Will open pipe: " + this.pipe);

		//this.auxiliaryServer.express.set("port", this.pipe);

		// Create the HTTP server using the primary server instance
		this.httpServer = http.createServer(this.server.express);
		this.httpServer.on("listening", () => this.onListening(this, this.httpServer));
		this.httpServer.on("error", (error) => this.onError(this, this.httpServer, error));

		// Create the IPC server using the auxiliary server instance
		this.ipcServer = Net.createServer();
		//this.ipcServer = http.createServer(this.auxiliaryServer.express);
		this.ipcServer.on("listening", () => this.onIPCServerListening(this, this.ipcServer));
		this.ipcServer.on("connection", (socket) => this.onIPCServerConnection(this, this.ipcServer, socket));
		this.ipcServer.on("error", (error) => this.onIPCServerError(this, this.ipcServer, error));
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

	private onIPCServerListening(starter : ServerStarter, appServer : Net.Server) : void
	{
		console.log("IPC server listening");
	}

	private onIPCServerConnection(starter : ServerStarter, appServer : Net.Server, socket : Net.Socket) : void
	{
		console.log("IPC connection opened");

		socket.on("data", (data) => this.onIPCServerReadData(socket, data));
		socket.on("close", (withError) => this.onIPCServerConnectionClosed(socket, withError));
	
		socket.write("Connection established\n");
	}

	private onIPCServerReadData(socket : Net.Socket, data : Buffer)
	{
		console.log("IPC server received data: " + data.toString().trimRight());
	}

	private onIPCServerConnectionClosed(socket : Net.Socket, withError : boolean)
	{
		console.log("IPC connection closed");
		if (withError)
			console.log("->  With errors");
	}

	private onIPCServerError(starter : ServerStarter, appServer : Net.Server, error : Error) : void
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
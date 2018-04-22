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
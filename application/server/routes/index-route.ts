import * as express from "express";

export default class IndexRoute
{
	private router : express.Router;

	public constructor()
	{
		this.router = express.Router();
		// TODO: routes should reflect the client-side routes defined in routing.module.ts
		this.router.get("/", this.handler);
		this.router.get("/test", this.handler);
	}

	private handler(request : express.Request, response : express.Response, next : express.NextFunction) : void
	{
		response.render("index", {title: "Express"});
	}

	public getRouter() : express.Router
	{
		return this.router;
	}
}

/*var express = require('express');
var router = express.Router();

// GET home page.
router.get('/', function(req, res, next) {
res.render('index', { title: 'Express' });
});

module.exports = router;*/
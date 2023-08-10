const jsonServer = require("json-server");
const jwt = require("jsonwebtoken");
const fs = require("fs");
const express = require("express");

const server = jsonServer.create();
const router = jsonServer.router("db.json");
const middlewares = jsonServer.defaults();
const AUTH_EXPIRATION = "15min";

server.use(middlewares);
server.use(express.json());

const SECRET_KEY = "my-secret-key";

server.post("/auth/login", (req, res) => {
  const { login, password } = req.body;

  fs.readFile("db.json", (err, data) => {
    if (err) throw err;

    const usersData = JSON.parse(data);
    const users = usersData.users;
    const user = users.find(
      (u) => u.login === login && u.password === password
    );

    if (user) {
      const access_token = jwt.sign({ login, role: user.role }, SECRET_KEY, {
        expiresIn: AUTH_EXPIRATION,
      });
      const refresh_token = jwt.sign({ login, role: user.role }, SECRET_KEY);
      res.json({ access_token, refresh_token });
    } else {
      res.sendStatus(401);
    }
  });
});

server.post("/auth/refresh", (req, res) => {
  const { refresh_token } = req.body;

  if (refresh_token) {
    jwt.verify(refresh_token, SECRET_KEY, (err, user) => {
      if (err) {
        return res.sendStatus(403);
      }

      const new_access_token = jwt.sign(
        { email: user.email, role: user.role },
        SECRET_KEY,
        {
          expiresIn: AUTH_EXPIRATION,
        }
      );
      res.json({ access_token: new_access_token });
    });
  } else {
    res.sendStatus(401);
  }
});

const validateJWT = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader.split(" ")[1];

  if (token) {
    jwt.verify(token, SECRET_KEY, (err, user) => {
      if (err) {
        return res.sendStatus(403);
      }
      req.user = user;
      next();
    });
  } else {
    res.sendStatus(401);
  }
};

server.use("/db", validateJWT, router);
server.use("/users", validateJWT, router);

server.listen(3030, () => {
  console.log("JSON Server is running on port 3030");
});

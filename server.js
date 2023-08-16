const jsonServer = require("json-server");
const jwt = require("jsonwebtoken");
const fs = require("fs").promises;
const express = require("express");
const path = require("path");

const UPLOADS_PATH = path.join(__dirname, "uploads");
const DB_PATH = "db.json";
const SECRET_KEY = "my-secret-key";
const AUTH_EXPIRATION = "15min";

const server = jsonServer.create();
const router = jsonServer.router(DB_PATH);
const middlewares = jsonServer.defaults();

server.use(middlewares);
server.use(express.json({ limit: "25mb" }));
server.use(express.urlencoded({ limit: "25mb", extended: true }));

// Auth routes
server.post("/auth/login", login);
server.post("/auth/refresh", refreshToken);

// Users routes
server.post("/users/:login/photo", uploadUserPhoto);

// JWT validation middleware
server.use("/db", validateJWT, router);
server.use("/users", validateJWT, router);

// Static route for uploads
server.use("/uploads", express.static(UPLOADS_PATH));

// Start the server
server.listen(3030, () => {
  console.log("JSON Server is running on port 3030");
});

async function login(req, res) {
  const { login, password } = req.body;
  const usersData = JSON.parse(await fs.readFile(DB_PATH, "utf8"));
  const user = usersData.users.find(
    (u) => u.login === login && u.password === password
  );

  if (user) {
    const tokens = generateTokensForUser(login, user.role);
    const user_information = getUserInfo(user);
    res.json({ ...tokens, user: user_information });
  } else {
    res.sendStatus(401);
  }
}

function refreshToken(req, res) {
  const { refresh_token } = req.body;

  if (refresh_token) {
    jwt.verify(refresh_token, SECRET_KEY, (err, user) => {
      if (err) return res.sendStatus(403);
      const new_access_token = generateAccessToken(user.email, user.role);
      res.json({ access_token: new_access_token });
    });
  } else {
    res.sendStatus(401);
  }
}

async function uploadUserPhoto(req, res) {
  const userLogin = req.params.login;
  const { photo } = req.body;

  if (!photo) return res.status(400).send("Nenhuma foto enviada.");

  const imagePath = path.join(UPLOADS_PATH, `${userLogin}.jpg`);
  const imageUrl = `/uploads/${userLogin}.jpg`;

  await savePhoto(imagePath, photo);
  await updateUserPhotoInDb(userLogin, imageUrl);

  res.status(200).json({ photo: imageUrl });
}

function validateJWT(req, res, next) {
  const token = getTokenFromHeader(req);

  if (token) {
    jwt.verify(token, SECRET_KEY, (err, user) => {
      if (err) return res.sendStatus(403);
      req.user = user;
      next();
    });
  } else {
    res.sendStatus(401);
  }
}

function generateTokensForUser(login, role) {
  const access_token = generateAccessToken(login, role);
  const refresh_token = jwt.sign({ login, role }, SECRET_KEY);
  return { access_token, refresh_token };
}

function generateAccessToken(login, role) {
  return jwt.sign({ login, role }, SECRET_KEY, { expiresIn: AUTH_EXPIRATION });
}

function getUserInfo(user) {
  const { login, name, cpf, registration, email, photo } = user;
  return { login, name, cpf, registration, email, photo };
}

async function savePhoto(imagePath, photo) {
  const imageBuffer = Buffer.from(photo, "base64");
  await fs.writeFile(imagePath, imageBuffer);
}

async function updateUserPhotoInDb(userLogin, imageUrl) {
  const usersData = JSON.parse(await fs.readFile(DB_PATH, "utf8"));
  const user = usersData.users.find((u) => u.id == userLogin);

  if (!user) throw new Error("Usuário não encontrado.");

  user.photo = imageUrl;
  await fs.writeFile(DB_PATH, JSON.stringify(usersData));
}

function getTokenFromHeader(req) {
  const authHeader = req.headers["authorization"];
  return authHeader && authHeader.split(" ")[1];
}

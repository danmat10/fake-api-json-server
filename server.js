const jsonServer = require("json-server");
const jwt = require("jsonwebtoken");
const fs = require("fs").promises;
const express = require("express");
const path = require("path");
const multer = require("multer");
const axios = require("axios");

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "uploads/");
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + "-" + file.originalname);
  },
});
const upload = multer({ storage: storage });

const UPLOADS_PATH = path.join(__dirname, "uploads");
const DB_PATH = "db.json";
const SECRET_KEY = "my-secret-key";
const AUTH_EXPIRATION = "15min";

const server = jsonServer.create();
const router = jsonServer.router(DB_PATH);
const middlewares = jsonServer.defaults();

server.use(middlewares);

// Users routes
server.post(
  "/api/users/:login",
  validateJWT,
  upload.single("photo"),
  uploadUserPhoto
);

server.use(jsonServer.bodyParser);
server.use((req, res, next) => {
  if (req.method === "POST" && req.path === "/api/users") {
    req.body.password = "123456";
  }
  next();
});

// Auth routes
server.post("/api/auth/login", login);
server.post("/api/auth/refreshToken", refreshToken);
server.put(
  "/api/users/:login/change-password",
  validateJWT,
  changeUserPassword
);
server.get("/api/users/:login/foto", getPhoto);

// JWT validation middleware
server.use("/api", validateJWT, router);
server.use("/users", validateJWT, router);

// Static route for uploads
server.use("/uploads", express.static(UPLOADS_PATH));

// Start the server
server.listen(3030, () => {
  console.log("JSON Server is running on port 3030");
});

async function getPhoto(req, res) {
  const userLogin = req.params.login;

  try {
    // Ler os dados do arquivo db.json
    const usersData = JSON.parse(await fs.readFile(DB_PATH, "utf8"));

    // Procura o usuário pelo ID (login)
    const user = usersData.users.find((u) => u.id == userLogin);

    if (!user) {
      return res.status(404).send("Usuário não encontrado.");
    }

    // Obter o caminho da foto
    if (!user.photo) {
      return res.status(404).send("Foto não encontrada.");
    }
    const photoPath = path.join(UPLOADS_PATH, user.photo);
    // Verificar se a foto existe
    try {
      res.sendFile(photoPath, (err) => {
        if (err) {
          res.status(404).send("Foto não encontrada.");
        }
      });
    } catch (err) {
      res.status(404).send("Foto não encontrada.");
    }
  } catch (error) {
    console.error("Erro ao obter a foto:", error);
    res.status(500).send("Erro interno do servidor.");
  }
}

async function changeUserPassword(req, res) {
  const userLogin = req.params.login;
  const { currentPassword, newPassword1 } = req.body;

  if (!currentPassword || !newPassword1) {
    return res.status(400).send("Senha atual e nova senha são necessárias.");
  }

  try {
    const usersData = JSON.parse(await fs.readFile(DB_PATH, "utf8"));
    const user = usersData.users.find((u) => u.id == userLogin);

    if (!user) {
      return res.status(404).send("Usuário não encontrado.");
    }

    if (user.password !== currentPassword) {
      return res.status(400).send("Senha atual incorreta.");
    }

    // Atualiza a senha do usuário
    user.password = newPassword1;

    // Salva a atualização no db.json
    await fs.writeFile(DB_PATH, JSON.stringify(usersData));

    res.status(200).send("Senha atualizada com sucesso!");
  } catch (error) {
    console.error("Erro ao alterar a senha:", error);
    res.status(500).send("Erro interno do servidor.");
  }
}

async function login(req, res) {
  const { login, password } = req.body;
  const usersData = JSON.parse(await fs.readFile(DB_PATH, "utf8"));
  const user = usersData.users.find(
    (u) =>
      (u.nrMatricula == login && u.password == password) ||
      (u.nrCpf == login && u.password == password)
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
  const { refreshToken } = req.body;

  if (refreshToken) {
    jwt.verify(refreshToken, SECRET_KEY, (err, user) => {
      if (err) return res.sendStatus(403);
      const new_access_token = generateAccessToken(user.email, user.role);
      res.json({ accessToken: new_access_token });
    });
  } else {
    res.sendStatus(401);
  }
}

async function uploadUserPhoto(req, res) {
  const userLogin = req.params.login;
  const photo = req.file;
  const token = getTokenFromHeader(req);

  if (!photo) {
    return res.status(400).send("Nenhuma foto enviada.");
  }

  try {
    const photoPath = photo.path.replace("uploads\\", "");
    await updateUserPhotoInDb(userLogin, photoPath, token);
    res.status(200).json({ photo: photoPath });
  } catch (error) {
    console.error("Erro ao salvar foto:", error);
    res.status(500).send("Erro interno do servidor.");
  }
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
  const accessToken = generateAccessToken(login, role);
  const refreshToken = jwt.sign({ login, role }, SECRET_KEY);
  return { accessToken, refreshToken };
}

function generateAccessToken(login, role) {
  return jwt.sign({ login, role }, SECRET_KEY, { expiresIn: AUTH_EXPIRATION });
}

function getUserInfo(user) {
  const { id, login, name, cpf, registration, email, photo } = user;
  return { id, login, name, cpf, registration, email, photo };
}

async function updateUserPhotoInDb(userLogin, imageUrl, token) {
  const user = { photo: imageUrl };

  try {
    await axios({
      method: "patch",
      url: `http://localhost:3030/api/users/${userLogin}`,
      data: user,
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });
  } catch (error) {
    console.error("Erro ao atualizar a foto do usuário:", error);
    throw error;
  }
}

function getTokenFromHeader(req) {
  const authHeader = req.headers["authorization"];
  return authHeader && authHeader.split(" ")[1];
}

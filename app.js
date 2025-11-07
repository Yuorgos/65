import express from "express";
import session from "express-session";
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import cookieParser from "cookie-parser";
import path from "path";
import dotenv from "dotenv";
import mongoose from "mongoose";

dotenv.config();

// 🔹 Підключення до MongoDB Atlas
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("✅ Підключено до MongoDB Atlas"))
  .catch((err) => console.error("❌ Помилка підключення до MongoDB:", err));

// 🔹 Налаштування Express
const app = express();
const PORT = process.env.PORT || 3000;
const __dirname = path.resolve();

app.set("view engine", "pug");
app.set("views", path.join(__dirname, "views"));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

// 🔹 Middleware для теми
app.use((req, res, next) => {
  res.locals.theme = req.cookies.theme || "light";
  next();
});

// 🔹 Сесії
app.use(
  session({
    secret: process.env.SESSION_SECRET || "superSecretSessionKey",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: false,
      maxAge: 1000 * 60 * 60, // 1 година
    },
  })
);

// 🔹 Ініціалізація Passport
app.use(passport.initialize());
app.use(passport.session());

// 🔹 Модель користувача (MongoDB)
const userSchema = new mongoose.Schema({
  username: String,
  password: String,
});
const User = mongoose.model("User", userSchema);

// 🔹 Локальна стратегія Passport
passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      const user = await User.findOne({ username, password });
      if (!user) {
        return done(null, false, { message: "Невірне ім’я користувача або пароль" });
      }
      return done(null, user);
    } catch (err) {
      return done(err);
    }
  })
);

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err);
  }
});

// 🔹 Головна сторінка
app.get("/", (req, res) => {
  res.render("index", { user: req.user });
});

// 🔹 Зміна теми
app.post("/set-theme", (req, res) => {
  const { theme } = req.body;
  res.cookie("theme", theme, { maxAge: 7 * 24 * 3600000 });
  res.redirect(req.get("referer") || "/");
});

// 🔹 Реєстрація
app.get("/register", (req, res) => res.render("register"));
app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  const existingUser = await User.findOne({ username });
  if (existingUser) {
    return res.status(400).send("Користувач уже існує");
  }

  const newUser = new User({ username, password });
  await newUser.save();
  res.redirect("/login");
});

// 🔹 Логін
app.get("/login", (req, res) => {
  res.render("login", { query: req.query });
});
app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/dashboard",
    failureRedirect: "/login?error=true",
  })
);

// 🔹 Вихід
app.get("/logout", (req, res, next) => {
  req.logout((err) => {
    if (err) return next(err);
    res.redirect("/");
  });
});

// 🔹 Middleware для захисту приватних сторінок
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.status(401).send("Неавторизовано. Увійдіть у систему.");
}

// 🔹 Приватна сторінка
app.get("/dashboard", ensureAuthenticated, (req, res) => {
  res.render("dashboard", { user: req.user });
});

// 🔹 Читання даних із MongoDB
app.get("/users", ensureAuthenticated, async (req, res) => {
  const users = await User.find();
  res.render("users", { users });
});

// 🔹 Запуск сервера
app.listen(PORT, () => console.log(`✅ Сервер запущено на порту ${PORT}`));

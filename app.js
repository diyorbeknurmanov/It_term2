const express = require("express");
const config = require("config");
const mongoose = require("mongoose");
const cookieParser = require("cookie-parser");

const indexRouter = require("./routes/index.routes");
const errorHandlingMiddleware = require("./middlewares/errors/error-handling.middleware");

const PORT = config.get("port") || 3030;

process.on("uncaughtException", (exception) => {
  console.log("uncaughtException:", exception.message);
});

process.on("unhandledRejection", (rejection) => {
  console.log("unhandledRejection", rejection);
});

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use("/api", indexRouter);
app.use(errorHandlingMiddleware); //error handling eng oxirida yozilishi kerak

async function start() {
  try {
    const uri = config.get("dbUri"); //mongodb://localhost:27017/fn21
    await mongoose.connect(uri);

    app.listen(PORT, () => {
      console.log(`Server running at port http://localhost:${PORT}`);
    });
  } catch (error) {
    console.log(error);
  }
}

start();

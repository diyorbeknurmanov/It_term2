const { sendErrorResponse } = require("../helpers/send_error_response");
const Author = require("../schemas/Author");
const { adminjwtservice } = require("../services/jwt.service.js");
const mailService = require("../services/mail.service.js");
const { authorValidation } = require("../validation/author.validation.js");
const bcrypt = require("bcrypt");
const config = require("config");
const jwt = require("jsonwebtoken");
const uuid = require("uuid");

const create = async (req, res) => {
  try {
    const { error, value } = authorValidation(req.body);

    if (error) {
      sendErrorResponse(error, res);
    }

    const hashedPassword = bcrypt.hashSync(value.password, 7);
    const activation_link = uuid.v4();
    const newAuthor = await Author.create({
      ...value,
      password: hashedPassword,
      activation_link,
    });

    const link = `${config.get(
      "api_url"
    )}/api/author/activate/${activation_link}`;

    await mailService.sendMail(value.email, link);

    res.status(201).send({ message: "New Author added", newAuthor });
  } catch (error) {
    return sendErrorResponse(error, res);
  }
};

const loginAuthor = async (req, res) => {
  try {
    const { email, password } = req.body;
    const author = await Author.findOne({ email });

    if (!author) {
      return res.status(401).send({ message: "Email yoki password noto'g'ri" });
    }
    const validPassword = bcrypt.compareSync(password, author.password);

    if (!validPassword) {
      return res.status(401).send({ message: "Email yoki password noto'g'ri" });
    }

    const payload = {
      id: author._id,
      email: author.email,
      is_active: author.is_active,
      is_expert: author.is_expert,
    };

    // const token = jwt.sign(payload, config.get("tokenKey"), {
    //   expiresIn: config.get("tokenExpTime"),
    // });

    const tokens = adminjwtservice.generateTokens(payload);
    author.refresh_token = tokens.refreshToken;
    await author.save();

    res.cookie("refreshToken", tokens.refreshToken, {
      httpOnly: true,
      maxAge: config.get("cookie_refresh_time"),
    });

    //====================== TEST UCHUN =========================//

    // try {
    //   setTimeout(function () {
    //     throw new Error("UncaughtException example");
    //   }, 1000);
    // } catch (error) {}

    // new Promise((_, reject) => {
    //   reject(new Error("UnHandledRejection example"));
    // });
    //====================== TEST UCHUN =========================//

    res.status(201).send({
      message: "Tizimga xush kelibsiz",
      id: author.id,
      accessToken: tokens.accessToken,
    });
  } catch (error) {
    return sendErrorResponse(error, res);
  }
};

const getAll = async (req, res) => {
  let { limit, offset } = req.query;
  try {
    limit = limit ? limit : 10;
    offset = offset ? offset : 1;

    const data = await Author.find({})
      .limit(limit)
      .skip((offset - 1) * limit);

    res.status(200).send({ data });
  } catch (error) {
    sendErrorResponse(error, res);
  }
};

const getOne = async (req, res) => {
  try {
    const { id } = req.params;
    const author = await Author.findById(id);

    res.status(200).send({ author });
  } catch (error) {
    sendErrorResponse(error, res);
  }
};

const remove = async (req, res) => {
  try {
    const { id } = req.params;
    const deletedItem = await Author.findByIdAndDelete(id);

    res.status(200).send({ message: "Author deleted", deletedItem });
  } catch (error) {
    sendErrorResponse(error, res);
  }
};

const update = async (req, res) => {
  try {
    const { id } = req.params;

    const { error, value } = authorValidation(req.body);

    if (error) {
      sendErrorResponse(error, res);
    }

    const updatedItem = await Author.findByIdAndUpdate(id, value);

    res.status(200).send({ message: "Author updated", updatedItem });
  } catch (error) {
    sendErrorResponse(error, res);
  }
};

const logoutAuthor = async (req, res) => {
  try {
    console.log(req.cookies);
    console.log(req.headers.cookie);

    const { refreshToken } = req.cookies;

    if (!refreshToken) {
      return res
        .status(400)
        .send({ message: "Cookieda refresh token topilmadi" });
    }

    const author = await Author.findOneAndUpdate(
      { refresh_token: refreshToken },
      { refresh_token: "" },
      { new: true }
    );

    if (!author) {
      return res.status(400).send({ message: "Token noto'g'ri" });
    }

    res.clearCookie("refreshToken");
    res.send({ author });
  } catch (error) {
    return sendErrorResponse(error, res);
  }
};

const refreshAuthorToken = async (req, res) => {
  try {
    const { refreshToken } = req.cookies;

    if (!refreshToken) {
      return res
        .status(400)
        .send({ message: "Cookieda refresh token topilmadi" });
    }

    await adminjwtservice.verifyRefreshToken(refreshToken);

    const author = await Author.findOne({ refresh_token: refreshToken });

    if (!author) {
      return res.status(401).send({ message: "Refresh token topilmadi" });
    }

    const payload = {
      id: author._id,
      email: author.email,
      is_active: author.is_active,
      is_expert: author.is_expert,
    };

    const tokens = adminjwtservice.generateTokens(payload);
    author.refresh_token = tokens.refreshToken;
    await author.save();

    res.cookie("refreshToken", tokens.refreshToken, {
      httpOnly: true,
      maxAge: config.get("cookie_refresh_time"),
    });

    res.status(201).send({
      message: "Tokenlar yangilandi",
      id: author.id,
      accessToken: tokens.accessToken,
    });
  } catch (error) {
    return sendErrorResponse(error, res);
  }
};

const authorActivate = async (req, res) => {
  try {
    const { link } = req.params;
    const author = await Author.findOne({ activation_link: link });

    if (!author) {
      return res.status(400).send({ message: "Avtor link noto'g'ri" });
    }

    if (author.is_active) {
      return res.status(400).send({ message: "Avtor avval faollashtirilgan" });
    }

    author.is_active = true;
    await author.save();
    res.send({ message: "Avtor faollashtirildi" });
  } catch (error) {
    sendErrorResponse(error, res);
  }
};

module.exports = {
  create,
  getAll,
  getOne,
  remove,
  update,
  loginAuthor,
  logoutAuthor,
  refreshAuthorToken,
  authorActivate,
};

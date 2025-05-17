const { sendErrorResponse } = require("../helpers/send_error_response");
const bcrypt = require("bcrypt");
const Admin = require("../schemas/Admin");
const config = require("config");
const mailService = require("../services/mail.service");
const jwt = require("jsonwebtoken");
const uuid = require("uuid");
const { adminjwtservice } = require("../services/jwt.service");

const create = async (req, res) => {
  try {
    const data = req.body;

    const hashedPassword = bcrypt.hashSync(data.password, 10);
    const activation_link = uuid.v4();

    const newAdmin = await Admin.create({
      ...data,
      password: hashedPassword,
      activation_link,
    });

    const link = `${config.get(
      "api_url"
    )}/api/admin/activate/${activation_link}`;

    await mailService.sendMail(data.email, link);

    res.status(201).send({ message: "New Admin added", newAdmin });
  } catch (error) {
    return sendErrorResponse(error, res);
  }
};

const login = async (req, res) => {
  try {
    const { email, password } = req.body;
    const admin = await Admin.findOne({ email });

    if (!admin) {
      return res.status(401).send({ message: "Email yoki password noto'g'ri" });
    }
    const validPassword = bcrypt.compareSync(password, admin.password);

    if (!validPassword) {
      return res.status(401).send({ message: "Email yoki password noto'g'ri" });
    }

    const payload = {
      id: admin._id,
      email: admin.email,
      is_active: admin.is_active,
      is_creator: admin.is_creator,
    };

    const tokens = adminjwtservice.generateTokens(payload);
    admin.refresh_token = tokens.refreshToken;
    await admin.save();

    res.cookie("refreshToken", tokens.refreshToken, {
      httpOnly: true,
      maxAge: config.get("cookie_refresh_time"),
    });

    res.status(201).send({
      message: "Tizimga xush kelibsiz",
      id: admin.id,
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

    const data = await Admin.find({})
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
    const admin = await Admin.findById(id);

    res.status(200).send({ admin });
  } catch (error) {
    sendErrorResponse(error, res);
  }
};

const remove = async (req, res) => {
  try {
    const { id } = req.params;
    const deletedItem = await Admin.findByIdAndDelete(id);

    res.status(200).send({ message: "Admin deleted", deletedItem });
  } catch (error) {
    sendErrorResponse(error, res);
  }
};

const update = async (req, res) => {
  try {
    const { id } = req.params;

    const updatedItem = await Admin.findByIdAndUpdate(id, req.body);

    res.status(200).send({ message: "Admin updated", updatedItem });
  } catch (error) {
    sendErrorResponse(error, res);
  }
};

const logoutAdmin = async (req, res) => {
  try {
    const { refreshToken } = req.cookies;

    if (!refreshToken) {
      return res
        .status(400)
        .send({ message: "Cookieda refresh token topilmadi" });
    }

    const admin = await Admin.findOneAndUpdate(
      { refresh_token: refreshToken },
      { refresh_token: "" },
      { new: true }
    );

    if (!admin) {
      return res.status(400).send({ message: "Token noto'g'ri" });
    }

    res.clearCookie("refreshToken");
    res.send({ admin });
  } catch (error) {
    return sendErrorResponse(error, res);
  }
};

const refreshAdminToken = async (req, res) => {
  try {
    const { refreshToken } = req.cookies;

    if (!refreshToken) {
      return res
        .status(400)
        .send({ message: "Cookieda refresh token topilmadi :(" });
    }

    await adminjwtservice.verifyRefreshToken(refreshToken);

    const admin = await Admin.findOne({ refresh_token: refreshToken });

    if (!admin) {
      return res.status(401).send({ message: "Refresh token topilmadi" });
    }

    const payload = {
      id: admin._id,
      email: admin.email,
      is_active: admin.is_active,
      is_creator: admin.is_creator,
    };

    const tokens = adminjwtservice.generateTokens(payload);
    admin.refresh_token = tokens.refreshToken;
    await admin.save();

    res.cookie("refreshToken", tokens.refreshToken, {
      httpOnly: true,
      maxAge: config.get("cookie_refresh_time"),
    });

    res.status(201).send({
      message: "Tokenlar yangilandi",
      id: admin.id,
      accessToken: tokens.accessToken,
    });
  } catch (error) {
    return sendErrorResponse(error, res);
  }
};

const adminActivate = async (req, res) => {
  const { link } = req.params;
  const admin = await Admin.findOne({ activation_link: link });

  if (!admin) {
    return res.status(400).send({ message: "avtor link notugri" });
  }

  if (admin.is_active) {
    return res.status(400).send({ message: "avtor avval faollashtirilgan" });
  }

  admin.is_active = true;
  admin.save();
  res.status(200).send({ message: "avtor faollashtirildi" });
};

module.exports = {
  create,
  getAll,
  getOne,
  remove,
  update,
  login,
  logoutAdmin,
  refreshAdminToken,
  adminActivate,
};

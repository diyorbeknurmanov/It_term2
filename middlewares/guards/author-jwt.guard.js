const { sendErrorResponse } = require("../../helpers/send_error_response");
const jwt = require("jsonwebtoken");
const config = require("config");
const jwtService = require("../../services/jwt.service");

module.exports = async (req, res, next) => {
  try {
    const authorization = req.headers.authorization;
    console.log(authorization);

    if (!authorization) {
      return res
        .status(401)
        .send({ message: "Authorization header not found" });
    }
    const bearer = authorization.split(" ")[0];
    const token = authorization.split(" ")[1];

    if (bearer !== "Bearer" || !token) {
      return res.status(401).send({ message: "Bearer token not found" });
    }

    // const decodedPayload = jwt.verify(token, config.get("tokenKey"));
    const decodedPayload = await jwtService.verifyAccessToken(token);

    if (!decodedPayload.is_active) {
      return res.status(403).send({ msg: "Active bolmagan foydalanuvchi" });
    }

    req.author = decodedPayload;

    next();
  } catch (error) {
    sendErrorResponse(error, res);
  }
};

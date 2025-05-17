const { sendErrorResponse } = require("../../helpers/send_error_response");

module.exports = (req, res, next) => {
  try {
    //logika

    if (!req.author.is_expert) {
      return res
        .status(403)
        .send({
          message: "Ruxsat etilmagan foydalanuvchi. Siz expert emassiz",
        });
    }

    next();
  } catch (error) {
    sendErrorResponse(error, res);
  }
};

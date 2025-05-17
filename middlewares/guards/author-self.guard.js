const { sendErrorResponse } = require("../../helpers/send_error_response");

module.exports = (req, res, next) => {
  try {
    //logika

    if (req.params.id != req.author.id) {
        return res.status(403).send({message: "Ruxsat etilmagan foydalanuvchi. Faqat shaxsiy ma'lumotlarni ko'rish mumkin"})
    }

    next();
  } catch (error) {
    sendErrorResponse(error, res);
  }
};

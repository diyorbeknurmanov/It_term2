const Joi = require("joi");

exports.dictValidation = (body) => {
  const schema = Joi.object({
    term: Joi.string()
      .min(1)
      .message("IT Termin 1ta harfdan kam bo'lmasligi kerak")
      .required()
      .messages({
        "string.empty": "Dict bosh bolishi mumkin emas",
        "any.required": "Lug'at albatta kiritilishi kerak",
      }),
  });
  return schema.validate(body);
};

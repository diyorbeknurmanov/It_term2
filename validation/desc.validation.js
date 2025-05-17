const Joi = require("joi");

exports.descValidation = (body) => {
  const schema = Joi.object({
    desription: Joi.string()
      .min(1)
      .message("Description name 1ta harfdan kam bo'lmasligi kerak")
      .required(),
    category_id: Joi.string().required(),
  });
  return schema.validate(body);
};
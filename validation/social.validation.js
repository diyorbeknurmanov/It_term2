const Joi = require("joi");

exports.socailValidation = (body) => {
  const schema = Joi.object({
    name: Joi.string()
      .min(4)
      .message("Social name 4ta harfdan kam bo'lmasligi kerak")
      .required(),
    icon_file: Joi.string().required(),
  });
  return schema.validate(body);
};
const Joi = require("joi");

exports.categoryValidation = (body) => {
  const schema = Joi.object({
    name: Joi.string()
      .min(1)
      .message("Category name 1ta harfdan kam bo'lmasligi kerak")
      .required()
      .messages({
        "string.empty": "Category bosh bolishi mumkin emas",
        "any.required": "Name albatta kiritilishi kerak",
      }),
  });
  return schema.validate(body);
};

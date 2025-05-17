const Joi = require("joi");

exports.topicValidation = (body) => {
  const schema = Joi.object({
    title: Joi.string().required().min(1),
    text: Joi.string().required().min(1),
    created_date: Joi.date(),
    updated_date: Joi.date(),
    is_checked: Joi.boolean().default(false),
    is_approved: Joi.boolean().default(false),
  });
  return schema.validate(body, { abortEarly: false });
};

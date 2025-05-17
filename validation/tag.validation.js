const Joi = require("joi");

exports.tagValidation = (body) => {
  const schema = Joi.object({
    topic_id: Joi.string().required(),
    category_id: Joi.string().required(),
  });
  return schema.validate(body);
};

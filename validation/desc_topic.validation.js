const Joi = require("joi");

exports.descTopicValidation = (body) => {
  const schema = Joi.object({
    desc_id: Joi.string().required(),
    topic_id: Joi.string().required(),
  });
  return schema.validate(body);
};
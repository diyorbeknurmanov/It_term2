const Joi = require("joi");

exports.synonymValidation = (body) => {
  const schema = Joi.object({
    desc_id: Joi.string().required(),
    dict_id: Joi.string().required(),
  });
  return schema.validate(body);
};
const Joi = require("joi");

const authorFullName = (parent) => {
  return parent.first_name + " " + parent.last_name;
};

exports.authorValidation = (body) => {
  const schema = Joi.object({
    first_name: Joi.string(),
    last_name: Joi.string(),
    full_name: Joi.string().default(authorFullName),
    nick_name: Joi.string()
      .min(3)
      .message("Nick qisqa")
      .max(15)
      .message("Nick juda uzun"),
    email: Joi.string().email().lowercase(),
    phone: Joi.string(),
    password: Joi.string().pattern(new RegExp("^[a-zA-Z0-9]{3,30}$")),
    repeat_password: Joi.ref("password"),
    info: Joi.string(),
    position: Joi.string(),
    photo: Joi.string().default("/author/avatar.png"),
    is_expert: Joi.boolean().default(false),
    is_active: Joi.boolean().default(false),
    // gender: Joi.string().valid("erkak", "ayol"),
    // birth_date: Joi.date().max("31-12-2000"),
    // port: Joi.number().port(),
    // birth_year: Joi.number().integer().max(2020),
    // referred: Joi.boolean(),
    // referredDetails: Joi.string().when("referred", {
    //   is: true,
    //   then: Joi.string().required(),
    //   otherwise: Joi.string().optional(),
    // }),
    // colors: Joi.array().items(Joi.string(), Joi.number()),
    // is_yes: Joi.boolean().truthy("Yes", "Ha").valid(true),
  });
  return schema.validate(body, { abortEarly: false });
};

const { Schema, model } = require("mongoose");

const authorSchema = new Schema(
  {
    first_name: { type: String, trim: true },
    last_name: { type: String, trim: true },
    nick_name: { type: String, trim: true, unique: true },
    email: { type: String, trim: true, unique: true, required: true },
    phone: { type: String, trim: true, unique: true },
    password: { type: String },
    info: { type: String },
    position: { type: String },
    photo: { type: String },
    is_expert: { type: Boolean },
    is_active: { type: Boolean },
    refresh_token: { type: String },
    activation_link: { type: String },
  },
  {
    versionKey: false,
    timestamps: false,
  }
);

module.exports = model("author", authorSchema);

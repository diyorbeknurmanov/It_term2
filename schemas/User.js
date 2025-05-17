const { Schema, model } = require("mongoose");

const userSchema = new Schema(
  {
    name: { type: String, trim: true },
    email: { type: String, trim: true, unique: true, required: true },
    password: { type: String },
    info: { type: String },
    photo: { type: String },
    created_date: { type: Date },
    updated_date: { type: Date },
    is_active: { type: Boolean },
    refresh_token: { type: String },
  },
  {
    versionKey: false,
    timestamps: false,
  }
);

module.exports = model("user", userSchema);

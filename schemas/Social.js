const { Schema, model } = require("mongoose");

const socialSchema = new Schema({
  name: { type: String, required: true, trim: true },
  icon_file: { type: String },
});

module.exports = model("social", socialSchema);

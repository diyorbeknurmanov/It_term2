const { Schema, model } = require("mongoose");

const categorySchema = new Schema({
  name: { type: String, required: true, trim: true },
});

module.exports = model("category", categorySchema);

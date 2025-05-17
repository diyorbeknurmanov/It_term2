const { Schema, model } = require("mongoose");

const dictSchema = new Schema({
  term: { type: String, required: true, trim: true },
  letter: { type: String, uppercase: true },
});

module.exports = model("dictionary", dictSchema);

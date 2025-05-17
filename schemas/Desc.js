const { Schema, model } = require("mongoose");

const descSchema = new Schema({
  desc: { type: String, required: true, trim: true },
  category_id: { type: Schema.Types.ObjectId, ref: "category" },
});

module.exports = model("desc", descSchema);

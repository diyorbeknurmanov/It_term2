const { Schema, model } = require("mongoose");

const descSchema = new Schema({
  desc_id: { type: Schema.Types.ObjectId, ref: "desc" },
  dict_id: { type: Schema.Types.ObjectId, ref: "dictionary" },
});

module.exports = model("synonyms", descSchema);

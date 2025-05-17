const { Schema, model } = require("mongoose");

const descTopicSchema = new Schema({
  desc_id: { type: Schema.Types.ObjectId, ref: "desc" },
  topic_id: { type: Schema.Types.ObjectId, ref: "topic" },
});

module.exports = model("desc_topic", descTopicSchema);

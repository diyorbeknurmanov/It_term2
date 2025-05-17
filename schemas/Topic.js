const { Schema, model } = require("mongoose");

const topicSchema = new Schema(
  {
    title: { type: String, trim: true },
    text: { type: String },
    created_date: { type: Date },
    updated_date: { type: Date },
    is_checked: { type: Boolean },
    is_approved: { type: Boolean },
    author_id: { type: Schema.Types.ObjectId, ref: "author" },
  },
  {
    versionKey: false,
    timestamps: false,
  }
);

module.exports = model("topic", topicSchema);

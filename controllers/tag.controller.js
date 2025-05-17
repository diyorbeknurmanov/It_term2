const { sendErrorResponse } = require("../helpers/send_error_response");
const Desc_Topic = require("../schemas/Desc_Topic");
const Tag = require("../schemas/Tag");
const { tagValidation } = require("../validation/tag.validation");

const create = async (req, res) => {
  try {
    const { error, value } = tagValidation(req.body);

    if (error) {
      sendErrorResponse(error, res);
    }

    const newTag = await Tag.create(value);
    res.status(201).send({ message: "New Tag added", newTag });
  } catch (error) {
    sendErrorResponse(error, res);
  }
};

const getAll = async (req, res) => {
  let { limit, offset } = req.query;
  try {
    limit = limit ? limit : 10;
    offset = offset ? offset : 1;

    const data = await Tag.find({})
      .populate("topic_id")
      .populate("category_id")
      .limit(limit)
      .skip((offset - 1) * limit);

    res.status(200).send({ data });
  } catch (error) {
    sendErrorResponse(error, res);
  }
};

const getOne = async (req, res) => {
  try {
    const { id } = req.params;
    const tag = await Tag.findById(id)
      .populate("topic_id")
      .populate("category_id");

    res.status(200).send({ tag });
  } catch (error) {
    sendErrorResponse(error, res);
  }
};

const remove = async (req, res) => {
  try {
    const { id } = req.params;
    const deletedItem = await Tag.findByIdAndDelete(id);

    res.status(200).send({ message: "Tag deleted", deletedItem });
  } catch (error) {
    sendErrorResponse(error, res);
  }
};

const update = async (req, res) => {
  try {
    const { id } = req.params;

    const { error, value } = tagValidation(req.body);

    if (error) {
      sendErrorResponse(error, res);
    }

    const updatedItem = await Tag.findByIdAndUpdate(id, value);

    res.status(200).send({ message: "Tag updated", updatedItem });
  } catch (error) {
    sendErrorResponse(error, res);
  }
};

module.exports = {
  create,
  getAll,
  getOne,
  remove,
  update,
};

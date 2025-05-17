const { sendErrorResponse } = require("../helpers/send_error_response");
const Topic = require("../schemas/Topic");
const { topicValidation } = require("../validation/topic.validation");

const create = async (req, res) => {
  try {
    const { error, value } = topicValidation(req.body);

    if (error) {
      sendErrorResponse(error, res);
    }

    const newTopic = await Topic.create(value);
    res.status(201).send({ message: "New Topic added", newTopic });
  } catch (error) {
    return sendErrorResponse(error, res);
  }
};

const getAll = async (req, res) => {
  let { limit, offset } = req.query;
  try {
    limit = limit ? limit : 10;
    offset = offset ? offset : 1;

    const data = await Topic.find({})
      .populate("author_id")
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
    const topic = await Topic.findById(id).populate("author_id");

    res.status(200).send({ topic });
  } catch (error) {
    sendErrorResponse(error, res);
  }
};

const remove = async (req, res) => {
  try {
    const { id } = req.params;
    const deletedItem = await Topic.findByIdAndDelete(id);

    res.status(200).send({ message: "Topic deleted", deletedItem });
  } catch (error) {
    sendErrorResponse(error, res);
  }
};

const update = async (req, res) => {
  try {
    const { id } = req.params;

    const { error, value } = topicValidation(req.body);

    if (error) {
      sendErrorResponse(error, res);
    }

    const updatedItem = await Topic.findByIdAndUpdate(id, value);

    res.status(200).send({ message: "Topic updated", updatedItem });
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

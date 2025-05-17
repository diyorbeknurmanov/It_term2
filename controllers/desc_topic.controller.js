const { sendErrorResponse } = require("../helpers/send_error_response");
const Desc_Topic = require("../schemas/Desc_Topic");
const { descTopicValidation } = require("../validation/desc_topic.validation");

const create = async (req, res) => {
  try {
    const { error, value } = descTopicValidation(req.body);

    if (error) {
      sendErrorResponse(error, res);
    }

    const newDescTopic = await Desc_Topic.create(value);
    res.status(201).send({ message: "New DescTopic added", newDescTopic });
  } catch (error) {
    sendErrorResponse(error, res);
  }
};

const getAll = async (req, res) => {
  let { limit, offset } = req.query;
  try {
    limit = limit ? limit : 10;
    offset = offset ? offset : 1;

    const data = await Desc_Topic.find({})
      .populate("desc_id")
      .populate("topic_id")
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
    const descTopic = await Desc_Topic.findById(id)
      .populate("desc_id")
      .populate("topic_id");

    res.status(200).send({ descTopic });
  } catch (error) {
    sendErrorResponse(error, res);
  }
};

const remove = async (req, res) => {
  try {
    const { id } = req.params;
    const deletedItem = await Desc_Topic.findByIdAndDelete(id);

    res.status(200).send({ message: "descTopic deleted", deletedItem });
  } catch (error) {
    sendErrorResponse(error, res);
  }
};

const update = async (req, res) => {
  try {
    const { id } = req.params;

    const { error, value } = descTopicValidation(req.body);

    if (error) {
      sendErrorResponse(error, res);
    }

    const updatedItem = await Desc_Topic.findByIdAndUpdate(id, value);

    res.status(200).send({ message: "DescTopic updated", updatedItem });
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

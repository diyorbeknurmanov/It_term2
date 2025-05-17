const { sendErrorResponse } = require("../helpers/send_error_response");
const Desc = require("../schemas/Desc");
const { descValidation } = require("../validation/desc.validation");

const create = async (req, res) => {
  try {
    const { error, value } = descValidation(req.body);

    if (error) {
      sendErrorResponse(error, res);
    }

    const newDesc = await Desc.create(value);
    res.status(201).send({ message: "New Term added", newDesc });
  } catch (error) {
    sendErrorResponse(error, res);
  }
};

const getAll = async (req, res) => {
  let { limit, offset } = req.query;
  try {
    limit = limit ? limit : 10;
    offset = offset ? offset : 1;

    const data = await Desc.find({})
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
    const desc = await Desc.findById(id).populate("category_id");

    res.status(200).send({ desc });
  } catch (error) {
    sendErrorResponse(error, res);
  }
};

const remove = async (req, res) => {
  try {
    const { id } = req.params;
    const deletedItem = await Desc.findByIdAndDelete(id);

    res.status(200).send({ message: "Description deleted", deletedItem });
  } catch (error) {
    sendErrorResponse(error, res);
  }
};

const update = async (req, res) => {
  try {
    const { id } = req.params;

    const { error, value } = descValidation(req.body);

    if (error) {
      sendErrorResponse(error, res);
    }

    const updatedItem = await Desc.findByIdAndUpdate(id, value);

    res.status(200).send({ message: "Description updated", updatedItem });
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

const { sendErrorResponse } = require("../helpers/send_error_response");
const Synonyms = require("../schemas/Synonyms");
const { synonymValidation } = require("../validation/synonyms.models");

const create = async (req, res) => {
  try {
    const { error, value } = synonymValidation(req.body);

    if (error) {
      sendErrorResponse(error, res);
    }

    const newDesc = await Synonyms.create(value);
    res.status(201).send({ message: "New Synonym added", newDesc });
  } catch (error) {
    sendErrorResponse(error, res);
  }
};

const getAll = async (req, res) => {
  let { limit, offset } = req.query;
  try {
    limit = limit ? limit : 10;
    offset = offset ? offset : 1;

    const data = await Synonyms.find({})
      .populate("desc_id")
      .populate("dict_id")
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
    const synonym = await Synonyms.findById(id)
      .populate("desc_id")
      .populate("dict_id");

    res.status(200).send({ synonym });
  } catch (error) {
    sendErrorResponse(error, res);
  }
};

const remove = async (req, res) => {
  try {
    const { id } = req.params;
    const deletedItem = await Synonyms.findByIdAndDelete(id);

    res.status(200).send({ message: "Synonym deleted", deletedItem });
  } catch (error) {
    sendErrorResponse(error, res);
  }
};

const update = async (req, res) => {
  try {
    const { id } = req.params;

    const { error, value } = synonymValidation(req.body);

    if (error) {
      sendErrorResponse(error, res);
    }

    const updatedItem = await Synonyms.findByIdAndUpdate(id, value);

    res.status(200).send({ message: "Synonym updated", updatedItem });
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

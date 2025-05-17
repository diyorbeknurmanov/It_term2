const { sendErrorResponse } = require("../helpers/send_error_response");
const Dict = require("../schemas/Dict");
const Joi = require("joi");
const { dictValidation } = require("../validation/dict.validation");

const create = async (req, res) => {
  try {
    const { error, value } = dictValidation(req.body);

    if (error) {
      sendErrorResponse(error, res);
    }

    const { term } = value;
    const newDict = await Dict.create({ term, letter: term[0] });
    res.status(201).send({ message: "New Term added", newDict });
  } catch (error) {
    return sendErrorResponse(error, res);
  }
};

const getAll = async (req, res) => {
  let { limit, offset } = req.query;
  try {
    limit = limit ? limit : 10;
    offset = offset ? offset : 1;

    const data = await Dict.find({})
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
    const dict = await Dict.findById(id);

    res.status(200).send({ dict });
  } catch (error) {
    sendErrorResponse(error, res);
  }
};

const remove = async (req, res) => {
  try {
    const { id } = req.params;
    const deletedItem = await Dict.findByIdAndDelete(id);

    res.status(200).send({ message: "Term deleted", deletedItem });
  } catch (error) {
    sendErrorResponse(error, res);
  }
};

const update = async (req, res) => {
  try {
    const { id } = req.params;
    // const { term } = req.body;

    const { error, value } = dictValidation(req.body);

    if (error) {
      sendErrorResponse(error, res);
    }

    const { term } = value;
    const updatedItem = await Dict.findByIdAndUpdate(id, {
      term,
      letter: term[0],
    });

    res.status(200).send({ message: "Term updated", updatedItem });
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

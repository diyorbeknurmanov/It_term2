const { sendErrorResponse } = require("../helpers/send_error_response");
const Category = require("../schemas/Category");
const { categoryValidation } = require("../validation/category.validation");

const create = async (req, res) => {
  try {
    const { error, value } = categoryValidation(req.body);

    if (error) {
      sendErrorResponse(error, res);
    }

    const newCateg = await Category.create(value);

    res.status(201).send({ message: "New category added", newCateg });
  } catch (error) {
    sendErrorResponse(error, res);
  }
};

const getAll = async (req, res) => {
  try {
    const data = await Category.find({});
    res.status(200).send({ data });
  } catch (error) {
    sendErrorResponse(error, res);
  }
};

const getOne = async (req, res) => {
  try {
    const { id } = req.params;
    const categ = await Category.findById(id);

    res.status(200).send({ categ });
  } catch (error) {
    sendErrorResponse(error, res);
  }
};

const remove = async (req, res) => {
  try {
    const { id } = req.params;
    const deletedItem = await Category.findByIdAndDelete(id);

    res.status(200).send({ message: "Category deleted", deletedItem });
  } catch (error) {
    sendErrorResponse(error, res);
  }
};

const update = async (req, res) => {
  try {
    const { error, value } = categoryValidation(req.body);

    if (error) {
      sendErrorResponse(error, res);
    }

    const updatedItem = await Category.findByIdAndUpdate(req.params, value);

    res.status(200).send({ message: "Category updated", updatedItem });
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

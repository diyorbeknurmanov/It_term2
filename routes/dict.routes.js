const {
  create,
  getAll,
  getOne,
  remove,
  update,
} = require("../controllers/dict.controller");
const authorExpertGuard = require("../middlewares/guards/author-expert.guard");
const authorJwtGuard = require("../middlewares/guards/author-jwt.guard");

const router = require("express").Router();

router.post("/", authorJwtGuard, authorExpertGuard, create);
router.get("/", getAll);
router.get("/:id", getOne);
router.delete("/:id", remove);
router.patch("/:id", update);

module.exports = router;

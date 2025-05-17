const {
  create,
  getAll,
  getOne,
  remove,
  update,
  loginAuthor,
  logoutAuthor,
  refreshAuthorToken,
  authorActivate,
} = require("../controllers/author.controller.js");
const authorJwtGuard = require("../middlewares/guards/author-jwt.guard.js");
const authorSelfGuard = require("../middlewares/guards/author-self.guard.js");

const router = require("express").Router();

router.post("/", create);
router.get("/", authorJwtGuard, getAll);
router.post("/login", loginAuthor);
router.post("/logout", logoutAuthor);
router.post("/refresh", refreshAuthorToken);
router.get("/activate/:link", authorActivate);
router.get("/:id", authorJwtGuard, authorSelfGuard, getOne);
router.delete("/:id", remove);
router.patch("/:id", update);

module.exports = router;

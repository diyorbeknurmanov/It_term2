const dictRouter = require("./dict.routes");
const categoryRouter = require("./category.routes");
const descRouter = require("./desc.routes");
const synonymsRouter = require("./synonyms.routes");
const authorRouter = require("./author.routes");
const socialRouter = require("./social.routes");
const topicRouter = require("./topic.routes");
const descTopicRouter = require("./desc_topic.routes");
const tagRouter = require("./tag.routes");
const adminRouter = require("./admin.routes");
const userRoutes = require("./user.routes");
const router = require("express").Router();

router.use("/dict", dictRouter);
router.use("/category", categoryRouter);
router.use("/description", descRouter);
router.use("/synonyms", synonymsRouter);
router.use("/author", authorRouter);
router.use("/social", socialRouter);
router.use("/topic", topicRouter);
router.use("/desc-topic", descTopicRouter);
router.use("/tag", tagRouter);
router.use("/admins", adminRouter);
router.use("/users", userRoutes);

module.exports = router;

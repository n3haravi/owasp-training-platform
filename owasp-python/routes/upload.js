const express = require("express");
const router = express.Router();

router.post("/", (req, res) => {
  console.log("Upload endpoint hit");

  // later: parse SonarQube JSON here
  res.json({ message: "File received" });
});

module.exports = router;

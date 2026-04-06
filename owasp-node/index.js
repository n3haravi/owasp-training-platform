const express = require("express");
const cors = require("cors");
const axios = require("axios");

const app = express();
app.use(cors());
app.use(express.json());

app.post("/generate", async (req, res) => {
  try {
    const response = await axios.post(
      "http://127.0.0.1:8000/generate",
      req.body,
      { headers: { "Content-Type": "application/json" } }
    );
    res.json(response.data);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Python backend error" });
  }
});

app.listen(5000, () => {
  console.log("Node backend running on http://localhost:5000");
});


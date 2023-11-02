const express = require('express');
const { validator } = require('./middleware/validation');

const {
  vulnerableUpdateProfile,
  updateProfileValidationRules,
  getProfile,
} = require('./controllers/vulnerable');

const app = express();
const port = 3000;

// use json requests
app.use(express.json())

// use validator
app.use(validator);

app.get("/me", getProfile)
app.post(
  "/me/update",
   updateProfileValidationRules,
   vulnerableUpdateProfile
)

// Start the server
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
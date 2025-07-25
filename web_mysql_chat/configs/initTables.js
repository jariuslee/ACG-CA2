// ##############################################################
// REQUIRE MODULES
// ##############################################################
const pool = require("../services/db");


// ##############################################################
// DEFINE SQL STATEMENTS
// ##############################################################



// ##############################################################
// RUN SQL STATEMENTS
// ##############################################################
pool.query(SQLSTATEMENT, (error, results, fields) => {
  if (error) {
    console.error("Error creating tables:", error);
  } else {
    console.log("Tables created successfully");
  }
  process.exit();
});
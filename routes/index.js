var express = require('express');
var router = express.Router();
var path = require('path');
var mysql = require('mysql');
var fs = require('fs');

const multer = require('multer');
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, './public/resources');
  },
  filename: (req, file, cb) => {
    console.log(file);
    cb(null, path.basename(file.originalname, '.pdf') + " - " + Date.now() + path.extname(file.originalname));
  }
})

const upload = multer({storage: storage});

/* GET home page. */
router.get('/', function(req, res, next) {
  res.render('index', { title: 'Express' });
});

router.get('/session_id', function(req, res, next) {

  var session_val = req.session.userID;
  console.log("UserID is: " +  req.session.userID);
  res.json(session_val);
});

router.post('/login', function(req, res, next) {
  console.log("TESTING LOG IN...");

  var username_check = req.body.username_test;
  var password_check = req.body.password_test;

  req.pool.getConnection(function(err, connection)
  {
    if (err)
    {
      console.log("Get connection error");
      res.sendStatus(500);
      return;
    }

    //Search 'users' database for a row with a matching users name and password to what was entered
    var query = "SELECT password, userID FROM users WHERE username='" + username_check + "';";
    connection.query(query, function(err, rows, fields)
    {
      connection.release(); //release the connection
      if (err)
      {
        console.log("Query error");
        res.sendStatus(500);
        return;
      }

      //FOR DEBUGGING!
      console.log("USERNAME: " + username_check + " | PASSWORD: " + password_check);

      //If any rows were returned with a matching password, it's a successful log in attempt
      if (rows.length > 0 && rows[0].password == password_check)
      {
        console.log("LOGIN WAS SUCCESSFUL!"); // DEBUG

        req.session.userID = rows[0].userID;
        console.log("Current user's userID: " + req.session.userID);
        res.sendStatus(204); //successful login
      }
      else
      {
        console.log("LOGIN FAILED :("); // DEBUG
        res.sendStatus(401); //failed login
      }


    });
  });
});

router.get('/create-account', function(req, res, next) {
  res.render('create-account', { title: 'Create Account' });
});

router.post('/signup', function(req, res, next) {
  console.log("TESTING SIGN UP...");

  var username_check = req.body.username_test;
  var password_check = req.body.password_test;
  var email_check = req.body.email_test;
  var access_check = req.body.user_access;

  var email_exists = false;
  var username_exists = false;

  //FOR DEBUGGING!
  console.log("USERNAME: " + username_check + " | PASSWORD: " + password_check + " | EMAIL: " + email_check + " | ADMINISTRATOR?: " + access_check);

  //STEP 1 -- CHECK IF users WITH THE INPUT EMAIL ALREADY EXISTS
  req.pool.getConnection(function(err, connection)
  {
    if (err)
    {
      console.log("Get connection error");
      res.sendStatus(500);
      return;
    }

    var query = "SELECT * FROM users WHERE email='" + email_check + "';";
    connection.query(query, function(err, rows, fields)
    {
      connection.release(); //release the connection
      if (err)
      {
        console.log("Query error");
        res.sendStatus(500);
        return;
      }

      //If any rows were returned with a matching email
      if (rows.length > 0)
      {
        email_exists = true;
        console.log("EMAIL ALREADY EXISTS!"); // DEBUG
      }
    });
  });

  //STEP 2 -- CHECK IF users WITH THE INPUT USERNAME ALREADY EXISTS
  req.pool.getConnection(function(err, connection)
  {
    if (err)
    {
      console.log("Get connection error");
      res.sendStatus(500);
      return;
    }

    var query = "SELECT * FROM users WHERE username='" + username_check + "';";
    connection.query(query, function(err, rows, fields)
    {
      connection.release(); //release the connection
      if (err)
      {
        console.log("Query error");
        res.sendStatus(500);
        return;
      }

      //If any rows were returned with a matching users name
      if (rows.length > 0)
      {
        username_exists = true;
        console.log("USERNAME ALREADY EXISTS!"); // DEBUG
      }
    });
  });


    //STEP 3 -- IF users'S EMAIL + EMAIL DON'T ALREADY EXIST, ENTER THEM INTO THE users DATABASE
    req.pool.getConnection(function(err, connection)
  {
    if (err)
    {
      console.log("Get connection error");
      res.sendStatus(500);
      return;
    }

    //If email or username already exist, the sign up attempt fails
    if (username_exists || email_exists)
    {
      console.log("SIGN UP FAILED :("); // DEBUG
      res.sendStatus(401); //failed signup
    }
    else
    {

      var query3 = "INSERT INTO users (username, password, email, access) VALUES (?, ?, ?, ?)";
      connection.query(query3, [username_check, password_check, email_check, access_check], function(err, rows, fields) {
        connection.release(); // release the connection
        if (err) {
          console.log("Query error at step 3");
          res.sendStatus(500);
          return;
        }

        console.log("SIGN UP WAS SUCCESSFUL!"); // DEBUG
        res.sendStatus(204); //successful signup
      });
    }

  });

});

router.get('/document', function(req, res, next) {
	res.sendFile(path.resolve(__dirname + '/../public/document.html'));
});

router.post('/redirect', function(req, res, next) {
    var username = req.body.username_test;
    var password = req.body.password_test;

    console.log("USERNAME: " + username + " | PASSWORD: " + password);

    req.pool.getConnection(function(err,connection)
    {
      if (err)
      {
        console.log("Get connection error");
        res.sendStatus(500);
        return;
      }

      var query = "SELECT access FROM users where username='" + username + "';";
      connection.query(query, function(err, rows, fields)
      {
        connection.release();
        if (err)
        {
          console.log("Query error");
          res.sendStatus(500);
          return;
        }

        var responseData = {
          redirectTo: '',
        };

        switch (rows[0].access) {
          case 'admin':
            console.log("is an admin");
            responseData.redirectTo = '/home-admin.html', // Specify the URL to redirect to
            res.json(responseData);
            break;
          case 'client':
            console.log("is a client");
            responseData.redirectTo = '/home-client.html', // Specify the URL to redirect to
            res.json(responseData);
            break;
          case 'annotator':
            console.log("is an annotator");
            responseData.redirectTo = '/home-annotator.html', // Specify the URL to redirect to
            res.json(responseData);
            break;
        }


      });
    });
});

router.post("/upload", upload.single('file'), (req, res) => {
  var uploadedFile = req.file;
  var ID = req.body.userID
  console.log("file name: " + uploadedFile.filename);
  console.log("userID: " + ID);

  req.pool.getConnection(function(err,connection)
  {
    if (err)
    {
      console.log("Get connection error");
      res.sendStatus(500);
      return;
    }

    var query = "INSERT INTO files (filename, userID) VALUES ('" + uploadedFile.filename + "', '" + ID + "');";
    connection.query(query, function(err, rows, fields)
    {
      connection.release();
      if (err)
      {
        console.log("Query error");
        res.sendStatus(500);
        return;
      }
      console.log("File uploaded");
      res.sendStatus(204);
    });
  });
});

router.post('/userfiles', function(req, res, next) {
  var id = req.body.userID;
  console.log("User ID is: " + id);
  req.pool.getConnection(function(err,connection) {
    if (err) {
      console.log(err);
      return;
    }

    var query = "select * from files where userID = ?";

      connection.query(query, [id], function(err, rows, fields) {
        connection.release();
        if (err) {
          console.log(err);
          return;
        }
        res.json(rows);
        });
    });
});

router.post('/download', function (req, res) {
  var id = req.body.fileID;
  console.log("File ID is: " + id);

  req.pool.getConnection(function (err, connection) {
    if (err) {
      console.log(err);
      return;
    }

    var query = "SELECT * FROM files WHERE fileID = ?";

    connection.query(query, [id], function (err, rows, fields) {
      connection.release();
      if (err) {
        console.log(err);
        return;
      }

      var name = rows[0].fileName;
      console.log(name);

      // Construct the file path
      const filePath = path.join("resources", name);
      res.status(200).json({ filePath: filePath, fileName: name });
    });
  });
});

router.get('/allFiles', function(req, res, next) {
  req.pool.getConnection(function(err,connection) {
    if (err) {
      console.log(err);
      return;
    }

    var query = "SELECT users.*, files.* FROM users INNER JOIN files ON users.userID = files.userID;";

      connection.query(query, function(err, rows, fields) {
        connection.release();
        if (err) {
          console.log(err);
          return;
        }
        res.json(rows);
        });
    });
});

router.post('/delete', function(req, res, next) {
  var id = req.body.fileID;
  console.log("Deleting File ID = " + id);
  req.pool.getConnection(function(err,connection) {
    if (err) {
      console.log(err);
      return;
    }

    var query = "DELETE FROM files WHERE fileID = ?;";

      connection.query(query, [id], function(err, rows, fields) {
        connection.release();
        if (err) {
          console.log(err);
          res.sendStatis(500);
          return;
        }
        res.sendStatus(204);
        });
    });
})

module.exports = router;

const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const swaggerDocjs = require("swagger-jsdoc");
const swaggerUi = require("swagger-ui-express");
const jwt = require('jsonwebtoken');
const multer = require('multer');
const { body, validationResult } = require('express-validator');
const path = require('path');
const validator = require('validator');

const cors = require('cors');
const secretkey = 'ffgfhhgjfgjs';


const app = express();
const port = process.env.PORT || 3000;

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// for data database
mongoose.connect('mongodb://127.0.0.1/authdata', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});


const db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB connection error:'));
db.once('open', () => {
  console.log('Connected to MongoDB');
});

// app.listen(port, () => {
//   console.log(`Server is running on http://localhost:${port}`);
// });

app.listen(port,'0.0.0.0', () => {
  console.log(`Server running on port ${port}`);
});

app.use(cors());

// swagger integration
const options = {
    definition: {
        openapi: '3.0.0',
        info: {
            title: 'My API Project Swagger Documentation',
            version: '1.0.0',
            description: 'API documentation for your Node.js API',
        },
    },

    security: [{ BearerAuth: [] }],
    apis: ["./app.js"],
}
    
const swaggerSpec = swaggerDocjs(options);

app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

// for auth model
const AuthData = require('./models/auth');


// function for hashpassword
async function hashpassword(password){
    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);
    return hashedPassword;
 }


// upload a file using multer

// Multer setup for file uploads
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/'); // Upload files to the 'uploads' directory
  },
  filename: function (req, file, cb) {
    // Use the current timestamp as the filename
    cb(null, Date.now() + path.extname(file.originalname));
  }
});

const upload = multer({ storage: storage });

/**
 * @swagger
 * /register:
 *   post:
 *     summary: Register a new user
 *     description: Endpoint to register a new user with profile image upload
 *     requestBody:
 *       content:
 *         multipart/form-data:
 *         
 *           schema:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *               email:
 *                 type: string
 *               password:
 *                 type: string
 *               username:
 *                 type: string
 *               mobile:
 *                 type: string
 *               address:
 *                 type: string
 *               profileImage:
 *                 type: string
 *                 format: binary
 *     responses:
 *       200:
 *         description: User registered successfully
 *       400:
 *         description: Bad request
 */


// Express route to register a user with validation
app.post(
  '/register', upload.single('profileImage'), 
  [ 
    body('username').isString().isLength({ min: 3 }),
    body('password').isString().isLength({ min: 6 }),
    body('mobile').isString().notEmpty().isLength({ min: 10, max: 12 }),
  ],
  async (req, res) => {
    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    try {
      const { name, username, password, email, mobile, address } = req.body;
      const profileImage = req.file ? req.file.filename : null;

      // Check if the username or email already exists
      const existingUser = await AuthData.findOne({ $or: [{ username }, { email }] });
      if (existingUser) {
        return res.status(400).json({ message: 'Username or email already exists' });
      }

      // Hash the password
      const hashedPassword = await hashpassword(password);

      // Get the current date
      const date = new Date();

      // Create a new user with the hashed password
      const newUser = new AuthData({ name, username, password: hashedPassword, email, mobile, address,date,profileImage });

      // Save the user to the database
      await newUser.save();

      res.status(201).json({ message: 'Registration successful', auth: newUser });
    } catch (error) {
      console.error(error);
      res.status(500).send('Internal Server Error');
    }
  }
);


// get all the registered user data

/**
 * @swagger
 * /users:
 *   get:
 *     summary: Get all registered users
 *     description: Retrieve data for all registered users
 *     responses:
 *       200:
 *         description: Successful response
 *         content:
 *           application/json:
 *             example:
 *               - name: 'User 1'
 *                 username: 'user1'
 *                 email: 'user1@example.com'
 *                 mobile: '1234567890'
 *                 address: '123 Main St, City'
 * 
 *                 
 *                
 *                               
 */
app.get('/users', async (req, res) => {
  try {
    const allUsers = await AuthData.find(); 
    res.json(allUsers);
  } catch (error) {
    console.error(error);
    res.status(500).send('Internal Server Error');
  }
});


 // compare password function
 async function comparePasswords(plaintextPassword, hashpassword) {
 
   // console.log('hashpassword',plaintextPassword,hashpassword);
     const match = await bcrypt.compare(plaintextPassword, hashpassword);
     // console.log("match",match);
     return match;
 }
 
// for login
/**
 * @swagger
 * /login:
 *   post:
 *     summary: Log in with a registered user
 *     description: Endpoint to log in with a registered user
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       200:
 *         description: User logged in successfully
 *       401:
 *         description: Unauthorized
 */


 // Express route to login a user
   app.post('/login', async (req, res) => {
     try {
       const { username, password } = req.body;
   // console.log("password",password,email)
 
       // Find the user in the database
       const user = await AuthData.findOne({ username:username });
   
       // If the user doesn't exist or the passwords don't match, send an error response
       if (!user || !(await comparePasswords(password, user.password))) {
         return res.status(401).send('Invalid credentials');
       }
       let jwtSecretKey = secretkey; 
        let data = { 
            username:user.username
        } 
      
        const token = jwt.sign(data, jwtSecretKey,{ expiresIn: '1h' }); 
       res.status(200).send({message:'Login successful', token:token});
     } catch (error) {
       console.error(error);
       res.status(500).send('Internal Server Error');
     }
   });
 

 /**
 * @swagger
 * components:
 *   securitySchemes:
 *     BearerAuth:
 *       type: http
 *       scheme: bearer
 * /profile:
 *   get:
 *     security:
 *       - BearerAuth: []
 *     summary: 
 *     description: 
 *     responses:
 *       201:
 *         description: 
 *       401:
 *         description: Unauthorized - Invalid token
 *       403:
 *         description: Forbidden - Token not provided
 */


// Middleware to authenticate JWT
function authenticateJWT(req, res, next) {
  let token = req.header('Authorization');
  token = token?.split(' ')[1];
  if (!token) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  
// console.log(token);
  jwt.verify(token, secretkey, (err, auth) => {
    if (err) {
      return res.status(403).json({ message: 'Forbidden' });
    }

    req.auth = auth;
    next();
  });
}

// app.get('/profile', authenticateJWT, (req, res) => {
//   res.status(200).json({ message: 'Protected data retrieved successfully' });
// });

// Example endpoint to get all data registered by the user
app.get('/profile', authenticateJWT, async (req, res) => {
  try {
    // Assuming you stored user information in a collection named 'users'
    const userData = await AuthData.find({ username: req.auth.username });

    res.status(200).json({ message: 'User data retrieved successfully', data: userData });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

// get the data by id

/**
 * @swagger
 * /users/{id}:
 *   get:
 *     summary: Get user data by ID
 *     description: Retrieve user data by providing the user ID
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         description: ID of the user to retrieve
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Successful response
 *         content:
 *           application/json:
 *             example:
 *               name: 'User 1'
 *               username: 'user1'
 *               email: 'user1@example.com'
 *               mobile: '1234567890'
 *               address: '123 Main St, City'
 *       400:
 *         description: User not found
 */
app.get('/users/:id', async (req, res) => {
  try {
    const userId = req.params.id;
    const user = await AuthData.findById(userId);

    if (user) {
      res.status(200).json(user);
    } else {
      res.status(400).json({ message: 'User not found' });
    }
  } catch (error) {
    console.error(error);
    res.status(500).send('Internal Server Error');
  }
});


// update the data 

/**
 * @swagger
 * /users/{id}:
 *   put:
 *     summary: Update a user by ID
 *     description: Update user data by providing the user ID
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         description: ID of the user to update
 *         
 *     requestBody:
 *       required: true
 *       content:
 *        
 *         multipart/form-data:
 *           schema:
 *             type: object
 *             properties:
 *               name:
 *                type: string
 *               username:
 *                 type: string
 *               
 *               email:
 *                 type: string
 *                 format: email
 *               mobile:
 *                 type: string
 *               address:
 *                 type: string
 *               profileImage:
 *                 type: string
 *                 format: binary
 *     responses:
 *       200:
 *         description: User updated successfully
 *       400:
 *         description: Bad request
 */


app.put(
  '/users/:id',
  upload.single('profileImage'),
  [
   
    body('username').isString().isLength({ min: 3 }),
    body('mobile').isString().notEmpty().isLength({ min: 10, max: 12 }),
    
  ],
  async (req, res) => {

    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    try {
      const userId = req.params.id;
      const updatedUserData = req.body;
      const profileImage = req.file ? req.file.filename : null;

      // If there is a profileImage in the request,then update the profileimage
      if (profileImage) {
        updatedUserData.profileImage = profileImage;
      }

      // Find the user with the provided ID and update user data
      const updatedUser = await AuthData.findByIdAndUpdate(userId, updatedUserData);

      if (updatedUser) {
        res.status(200).json({ message: 'User updated successfully', user: updatedUser });
      } else {
        res.status(400).json({ message: 'User not found' });
      }
    } catch (error) {
      console.error(error);
      res.status(500).send('Internal Server Error');
    }
  }
);

/**
 * @swagger
 * /users/{id}:
 *   delete:
 *     summary: Delete a user by ID
 *     description: Delete a user based on their unique identifier
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         description: The ID of the user to delete
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: User deleted successfully
 *       404:
 *         description: User not found
 *       500:
 *         description: Internal Server Error
 */
app.delete('/users/:id', async (req, res) => {
  try {
    const userId = req.params.id;
    const deletedUser = await AuthData.findByIdAndDelete(userId);
    
    if (!deletedUser) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    res.json({ message: 'User deleted successfully',deletedUser });
  } catch (error) {
    console.error(error);
    res.status(500).send('Internal Server Error');
  }
});


// upload a file using multer

// Multer configuration
// const storage = multer.diskStorage({
//   destination: function (req, file, cb) {
//     cb(null, 'uploads/');
//   },
//   filename: function (req, file, cb) {
//     cb(null, file.originalname);
//   },
// });

// const upload = multer({ storage: storage });

// /**
//  * @swagger
//  * /upload:
//  *   post:
//  *     summary: Upload a file
//  *     description: Endpoint to upload a file
//  *     requestBody:
//  *       content:
//  *         multipart/form-data:
//  *           schema:
//  *             type: object
//  *             properties:
//  *               file:
//  *                 type: string
//  *                 format: binary
//  *     responses:
//  *       200:
//  *         description: File uploaded successfully
//  */
// app.post('/upload', upload.single('file'), (req, res) => {
//   res.send('File uploaded successfully');
// });

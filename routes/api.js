const multer = require('multer');
const config = require('../config.json');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');
const jwt = require('jsonwebtoken');

// getting secret that is used to create auth tokens
const secret = process.env.SECRET || config.default_secret

// defining the properties (such as storage location, name and number
// of files that can be uploaded etc.) of the files that can be uploaded.
const upload = multer({
    storage: multer.diskStorage({
        destination: function(req, file, cb) {
            // constructing path to folder
            const folder = path.join(config.storage, req.body["patient_id"]);

            // creating folder
            fs.mkdirSync(folder, { recursive: true });

            // calling callback
            cb(null, folder);
        },
        filename: function(req, file, cb) {
            cb(null, file.originalname);
        }
    })
});
const uploadType = upload.fields([
    {name: 't1', maxCount: 1},
    {name: 't1ce', maxCount: 1},
    {name: 't2', maxCount: 1},
    {name: 'flair', maxCount: 1},
    {name: 'seg', maxCount: 1},
]);

const generateID = () => crypto.randomBytes(3).toString("hex");
const createToken = ({email, id}) => jwt.sign({
     email: email,
    _id: id
}, secret, {
    expiresIn: "24h"
})

module.exports = function(client, router) {

    /**
     * End point that is used to login. On a successful login, returns
     * a token.
     */
    router.post('/login', function(req, res) {
        // getting id and password from the request's body
        const { id, password }  = req.body;

        // getting the user info stored in db using the id
        client.hgetall(`${config.user_prefix}:${id}`, function (err, reply) {

            // checking if the reply from the db is empty
            if (! reply) {
                res.status(404).json({
                    success: false,
                    message: "User not found."
                });
            } else {
                // getting the hashed password from the db
                const hash = reply.password;

                // comparing the hashed password to the password given by the user in the request
                bcrypt.compare(password, hash, function (err, result) {

                    // if they match, return token
                    if (result === true) {
                        // sending response
                        res.status(200).json({
                            success: true,
                            token: createToken({email: reply.email, id: id})
                        });
                    } else {

                        // return error message with http status code 401 (Invalid credentials)
                        res.status(401).json({
                            success: false,
                            message: "Invalid password."
                        });
                    }
                });
            }
        });
    });

    /**
     * End point that is used to register. On a successful login, returns
     * a token.
     */
    router.post("/register", function(req, res) {
        // getting required information from the request's body
        const { id, password, first_name, last_name, department, email, phone } = req.body;

        // to hash password, takes plain text password and stores hash in hash parameter of the callback.
        bcrypt.hash(password, config.saltRounds, function (err, hash) {
            // adding user entry to database
            client.hmset(`${config.user_prefix}:${id}`, [
                'password', hash,
                'first_name', first_name,
                'last_name', last_name,
                'department', department,
                'email', email,
                'phone', phone
            ], function (err) {
                // if error occurred while adding, send error message with
                // http status code 500 (Internal server error)
                if (err)
                    res.status(500).json({
                        success: false,
                        message: err.toString()
                    });

                // else, send token.
                res.status(200).json({
                    success: true,
                    token: createToken({email: email, id: id})
                });
            })
        });
    })

    /**
     * Middleware to check validity of token
     */
    router.use(function(req, res, next) {
        // getting token from the request body, parameter or header
        const token = req.body.token || req.query.token || req.headers['x-access-token'];

        if (token) {
            // verifying token
            jwt.verify(token, secret, function(err, decoded) {
                if (err) {
                    // The token has expired or is invalid
                    // noinspection JSUnresolvedFunction
                    res.status(401).json({
                        success: false,
                        message: "Invalid token."
                    })
                }

                // adding the token contents in the req object
                req.token_contents = decoded;

                // calling the next route
                next();
            })
        }
        else {
            // no token provided
            // noinspection JSUnresolvedFunction
            res.status(401).json({
                success: false,
                message: "No token provided"
            })
        }
    })

    /**
     * End point to receive MRI scans.
     */
    router.post('/upload', uploadType, function (req, res) {

        // generating id for the medical record
        const id = generateID();

        // adding path to patient key in db
        client.hmset(`${config.record_prefix}:${id}`, [
            'mri_scans', path.join(config.storage, req.body['patient_id']).toString()
        ], function(err) {
            // if error occurred while adding, send error message with
            // http status code 500 (Internal server error)
            if (err)
                res.status(500).json({
                    success: false,
                    message: err.toString()
                });

            // else, send record id.
            res.status(200).json({
                success: true,
                record_id: id
            });
        });

        // redirecting request to model server
        res.redirect(307, `${config.model_server}/api/upload`);
    });

    /**
     * End point that is used to delete a user.
     */
    router.delete('/user/delete', function(req, res) {
        // getting the token contents from request
        const { token_contents } = req;

        // creating the key that is used to reference the user in the database
        const key = `${config.user_prefix}:${token_contents["_id"]}`

        // deleting user
        client.del(key, function(err) {
            // if error occurred while deleting, send error message with
            // http status code 500 (Internal server error)
            if (err)
                res.status(500).json({
                    success: false,
                    message: err.toString()
                });

            // else, send success message
            res.status(200).json({
                success: true
            });
        });
    })
    
    /**
     * End point to add a patient
     */
    router.post('/patient/add', function(req, res) {
        const { name, gender, dob, contact } = req.body;
        const id = generateID();
        const key = `patients:${id}`;

        client.hmset(key, [
            'name', name,
            'gender', gender,
            'dob', dob,
            'contact', contact
        ], function(err) {
            // if error occurred while adding, send error message with
            // http status code 500 (Internal server error)
            if (err)
                res.status(500).json({
                    success: false,
                    message: err.toString()
                });

            // else, send patient id.
            res.status(200).json({
                success: true,
                patient_id: id
            });
        });
    });

    /**
     * End point to update a medical record
     */
    router.post("/medical-record/update", function(req, res) {
        // getting info from body
        const { record_id, patient_id, diagnosis, symptoms, treatment } = req.body;

        // getting contents of token from request
        const { token_contents } = req;

        // getting doctor id (user id) from token
        const doctor_id = token_contents["_id"]

        // adding record entry to database
        client.hmset(`${config.record_prefix}:${record_id}`, [
            'doctor_id', doctor_id,
            'patient_id', patient_id,
            'diagnosis', diagnosis,
            'symptoms', symptoms,
            'treatment', treatment
        ], function (err) {
            // if error occurred while adding, send error message with
            // http status code 500 (Internal server error)
            if (err)
                res.status(500).json({
                    success: false,
                    message: err.toString()
                });

            // else, send success message.
            res.status(200).json({
                success: true,
                message: "added record successfully" //Display message
            });
        })
    });

    return router;
};

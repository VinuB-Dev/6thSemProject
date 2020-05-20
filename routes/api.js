const multer = require('multer');
const config = require('../config.json');
const bcrypt = require('bcryptjs');

// defining the names of the files and the number
// of the files that can be uploaded
const upload = multer();
const uploadType = upload.fields([
    {name: 't1', maxCount: 1},
    {name: 't1ce', maxCount: 1},
    {name: 't2', maxCount: 1},
    {name: 'flair', maxCount: 1},
    {name: 'seg', maxCount: 1},
]);

module.exports = function(client, router) {

    /**
     * End point to receive MRI scans.
     */
    router.post('/upload', uploadType, function (req, res) {
        // TODO: check validity of token

        // redirecting request to model server
        res.redirect(307, `${config.model_server}/api/upload`);
    });

    /**
     * End point that is used to login. On a successful login, returns
     * a token.
     */
    router.post('/login', function(req, res) {
        // getting id and password from the request's body
        const { id, password }  = req.body;

        // getting the user info stored in db using the id
        client.hgetall(`users:${id}`, function (err, reply) {

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
                        res.status(200).json({
                            success: true,
                            token: "some-super-secret-token" // TODO: send an actual token
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
            client.hmset(`users:${id}`, [
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
                    token: "some-super-secret-token" // TODO: send an actual token
                })
            })
        });
    })

    /**
     * End point that is used to delete a user.
     */
    router.delete('/user/delete', function(req, res) {
        // creating the key that is used to reference the user in the database
        const key = `users:${req.query.id}`

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
            })
        });
    })

    return router;
};

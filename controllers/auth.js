const { connect } = require('getstream');
const bcrypt = require('bcrypt');
const StreamChat = require('stream-chat');
const crypto = require('crypto');

const api_key = process.env.STREAM_API_KEY;
const api_secret = process.env.STREAM_API_SECRET;
const app_id = process.env.STREAM_APP_ID;

const signup = async(req, res) => {
    try {
        const {  fullName, username, password, phoneNumber } = req.body;

        const userId = crypto.randomBytes(16).toString('hex'); // to create random 16digit string

        const serverClient = connect(api_key, api_secret, app_id); // connect to stream

        const hashedPassword = await bcrypt.hash(password, 10); // to hash password 10 specified the level of encryption

        const token = serverClient.createUserToken(userId) //token for each user

        res.status(200).json({ token, fullName, username, userId, hashedPassword, phoneNumber }); //return data to frontend
    } catch (error) {
        console.log(error);

        res.status(500).json({ message: error});
    }
};

const login = async(req, res) => {
    try {
        const { username, password } = req.body;

        const serverClient = connect(api_key, api_secret, app_id);

        const client = StreamChat.getInstance(api_key, api_secret); //new instance of stream chat.

        const { users } = await client.queryUsers({ name: username }); //query users in the database to see if there's a match.

        if (!users.length()) return res.status(404).json({message: 'user not found'});

        const success = await bcrypt.compare(password, users[0].hashedPassword); //decrypt password and see if it match user's password.

        const token = serverClient.createUserToken(users[0].id); //create new user token and pass that specific user's i.d

        if (success) {
            res.status(200).json({ token, fullName: users[0].fullName, username, userId: users[0].id });
        } else {
            res.status(500).json({ message: 'incorrect passsword' });
        }
    } catch (error) {
        console.log(error);

        res.status(500).json({ message: error});
    }
};

 module.exports = { signup, login };

import express from 'express'
import cors from 'cors'
import dotenv from 'dotenv'
import mongoose from 'mongoose'
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'
import User from './model/usermodel.js'

dotenv.config()

const router = express.Router()
const app = express()
const SECRET_KEY = process.env.SECRET_KEY
const PORT = 5000 || process.env.PORT



app.use(cors())
app.use(express.json())


app.get('/', (req,res)=>{
    res.send('Hello World')
});

mongoose.connect(process.env.MONGO_URL)
.then(()=>{
    console.log('Connected to MongoDB')
})
.catch((err)=>{
    console.log(err)
})


// register
router.post('/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ name, email, password: hashedPassword });
        await newUser.save();
        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        res.status(500).json({ error: 'Error registering user' });
    }
});

// login
router.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        const token = jwt.sign({ userId: user._id }, SECRET_KEY, { expiresIn: '1hr' });
        res.status(200).json({ token: token });
    } catch (error) {
        res.status(500).json({ error: 'Error logging in' });
    }
});


// secure route
router.get('/profile', async (req, res) => {
    try {
        const token = req.headers.authorization.split(' ')[1];
        const decodedToken = jwt.verify(token, SECRET_KEY);
        const userId = decodedToken.userId;
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        res.status(200).json({ message: `Welcome, ${user.name}! This is a secure route.` });
    } catch (error) {
        res.status(401).json({ error: 'Unauthorized' });
    }
});

app.use('/', router)


app.listen(PORT,()=>{
    console.log(`Server is running on http://localhost:${PORT}`)
})
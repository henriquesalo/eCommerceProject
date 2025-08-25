import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import cookieParser from 'cookie-parser';
import morgan from 'morgan';
import helmet from 'helmet';
import connectDB from './config/connectDB.js';
import userRouter from './routes/user.route.js';

dotenv.config();

const app = express();
app.use(cors({
    credentials: true,
    origin: process.env.FRONTEND_URL
}));
app.use(express.json());
app.use(cookieParser());
app.use(morgan());
app.use(helmet({
    crossOriginResourcePolicy: false
}));

const PORT = 8080 || process.env.PORT;

app.get('/', (req, res) => {
    res.json({ 
        message: 'SERVIDOR COMUNICANDO' 
    });
});

app.use("/api/user", userRouter);

// fazendo a conexão no banco primeiro para depois iniciar o servidor
connectDB().then(() => {
    app.listen(PORT, () => {
        console.log(`NOSSO SERVIDOR ESTA RODANDO NA PORTA ${PORT}`);
    });
});
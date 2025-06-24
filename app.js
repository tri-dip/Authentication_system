import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import {_dirname} from "path";
import { fileURLToPath } from "url";
import env from "dotenv"

const app = express();
const port = 3000;

app.listen(`${port}`,()=>{
    console.log(`Server running on port ${port}`);
})
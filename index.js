import express from "express";
import ejs from "ejs";
import bcrypt from "bcrypt"
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken"
import mongoose, { Schema } from "mongoose";
import methodOverride from "method-override";
import dotenv from "dotenv";
dotenv.config()

const app = express();
app.use(express.static("Public"));
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(methodOverride('_method'));
app.use((req, res, next) => {
    // Allow public access to specific routes
    const publicRoutes = ["/login", "/register"];
    if (publicRoutes.some(route => req.path.startsWith(route))) {
        return next();
    }

    // Apply the authentication middleware for other routes
    authenticateToken(req, res, next);
});


app.set ("view engine", "ejs")

const dburl = process.env.MONGO_URI
mongoose.connect(dburl)

const RecordSchema = {
    username: String,
    amountOwe: [Number],
}

const UserSchema = new mongoose.Schema({
    username:{
        type: String,
        required: true,
        unique: true
    }, 
    email:{
        type: String,
        required: true,
        unique: true
    },
    password:{
        type: String,
        required: true
    }
});

const CreditRecord = mongoose.model("CreditRecord", RecordSchema);
const UserCredit = mongoose.model("UserCredit", UserSchema);



app.get('/favicon.ico', (req, res) => res.status(204).end());

app.get("/register", function(req, res){
    res.render("register")
})

app.get("/login", function(req, res){
    res.render("Login")
})

app.post("/register", async(req, res) => {
    try{
        const { username, email, password, confirmPassword } = req.body;

        if (!username || !email || !password || !confirmPassword){
            return res.status(400).send('All field are required')
        }

        if (password !== confirmPassword){
            return res.status(400).send("Password doesn't match");
           
        }
        
        const hashedPassword = await bcrypt.hash(password,10);
        const user = new UserCredit({username, email, password: hashedPassword});
        await user.save()
        res.status(200).send("Account Created Sucessfully, Now Proceed to Login")
        
    } catch (error) {
        if (error.code === 11000) {
            res.status(400).send("Username or email already exists");
        } else {
            console.error(error);
            res.status(500).send("Error registering user");
        }
    }
});

app.post("/login", async(req, res) =>{
    try{
        const { email, password} = req.body ;
        const user = await UserCredit.findOne({email});
        if(!user){
            return res.send("User not found")
        }
        const isMatch = await bcrypt.compare(password, user.password)
        if (!isMatch){
            res.send("Incorrect Password")
        }
        
        const token = jwt.sign(
            { id: user._id, username: user.username },
            process.env.JWT_SECRET || "mySecretKey", // Secret key
            { expiresIn: "1h" } // Token validity
        );
        // Set the token as an HTTP-only cookie
        res.cookie("authToken", token, {
            httpOnly: true,
            sameSite: "strict", // Ensures cookies are sent only with same-site requests
            secure: process.env.NODE_ENV === "production", // Use secure cookies in production
        });

        // Redirect to the home page
        res.redirect("/");
    }catch(error){
        res.send("Error while logging in ...")
    }
})

const authenticateToken = (req, res, next) => {
    const token = req.cookies.authToken;// Extract token from Authorization header
    
    if (!token) {
        return res.redirect("/login"); // Redirect to login if token is missing
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            return res.redirect("/login"); // Redirect if token is invalid
        }
        req.user = user; // Attach user info to the request
        next(); // Proceed to the next middleware or route
    });
};

app.get("/",authenticateToken, async(req, res) => {
    const users = CreditRecord.aggregate([
        {
            $project: {
                username: 1,
                totalAmountOwe: { $sum: "$amountOwe" }
            }
        }
    ])
    .then((users) => {
        res.render("home", {users, loggedInUser: req.user});
    })
    .catch(err => {
        console.log(err);
        res.status(500).send("Error while getting records");
    });
});

app.get ("/add",authenticateToken, function(req, res){
    res.render("add")
});

app.post("/add", function(req, res){
    const creditor = new CreditRecord({
        username: req.body.username,
        amountOwe: req.body.amount
    }) 
    creditor.save()
        .then((creditor) => {res.redirect("/")})
        .catch(err => { res.status(500).send("Error saving record")} )

});

app.get("/:id",authenticateToken, function(req, res) {
    CreditRecord.findById(req.params.id)
        .then(creditor => {
            if (creditor) {
                const totalAmountOwe = creditor.amountOwe.reduce((sum, amount) => sum + amount, 0);
                res.render("creditorDetails", {creditor, totalAmountOwe});
            } else {
                res.status(404).send("Creditor not found");
            }
        })
        .catch(err => {
            console.log(err);
            res.status(500).send("Unable to get creditor details");
        });
});

app.get("/update/:id",authenticateToken, function (req, res){
    res.render("update")
})


app.post("/update/:id", async (req, res) => {
    const id = req.params.id;
    if (!mongoose.Types.ObjectId.isValid(id)) {
        return res.status(400).json({ error: "Invalid ID format" });
    }

    try {
        const updatedRecord = await CreditRecord.findByIdAndUpdate(id, req.body, { new: true });
        if (!updatedRecord) {
            return res.status(404).json({ error: "Record not found" });
        }
        
        res.status(200).redirect(`/${id}`);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});


app.post('/delete/:id', async (req, res) => {
    const id = req.params.id;
    try {
      await CreditRecord.findByIdAndDelete(id);
      res.status(200).redirect('/');
    } catch (error) {
      res.status(500).send({ error: 'Error deleting record' });
    }
  });


const Port = process.env.port || 3000
app.listen(Port, function(){
    console.log(`Server started working at Port ${Port}`)
})

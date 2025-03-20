const express = require("express");
const cors = require("cors");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
const bodyParser = require("body-parser");
const nodemailer = require("nodemailer");
const jwt = require("jsonwebtoken");

require("dotenv").config();

const app = express();
const PORT = process.env.PORT;

app.use(cors({
    origin: '*'
}));
app.use(bodyParser.json()); 



const db = new sqlite3.Database("HRMdb.db", (err) => {
    if (err) {
        console.error("Failed to connect to the database");
    } else {
        console.log("Connected to HRMdb successfully");

        db.run(`
            CREATE TABLE IF NOT EXISTS Employee (
                ID INTEGER PRIMARY KEY AUTOINCREMENT,
                EmployeeID INTEGER UNIQUE NOT NULL, 
                FullName VARCHAR(24) NOT NULL,
                FirstName VARCHAR(24),
                LastName VARCHAR(24),
                WorkEmail VARCHAR(32) UNIQUE NOT NULL,
                Role TEXT DEFAULT 'Employee',
                designation VARCHAR(50) DEFAULT 'Software Developer',
                phone INTEGER,
                startdate DATE,
                Company VARCHAR(50) NOT NULL,
                Gender VARCHAR(10) NOT NULL,
                DateOfBirth DATE,
                Address TEXT,
                City TEXT,
                State TEXT,
                Country TEXT,
                PinCode INTEGER,
                About_Yourself ,
                Password TEXT NOT NULL,
                status TEXT,
                Enddate Date
             )`);
        db.run(`CREATE TABLE IF NOT EXISTS AttendanceLog (
                AttendanceLogID INTEGER PRIMARY KEY AUTOINCREMENT,
                EmployeeID VARCHAR(10) NOT NULL,
                WorkEmail VARCHAR(32) NOT NULL,
                Logdate DATE NOT NULL,
                LogTime TIME NOT NULL,
                EffectiveHours TEXT NOT NULL,
                GrossHours TEXT NOT NULL,
                ArrivalStatus TEXT,
                LeaveStatus TEXT NOT NULL,
                Logstatus TEXT NOT NULL,
                FOREIGN KEY (EmployeeID) REFERENCES Employee(EmployeeID) 
        )`);

        db.run(`CREATE TABLE IF NOT EXISTS Events(
            EventsID INTEGER PRIMARY KEY AUTOINCREMENT,
            EmployeeID VARCHAR(10) NOT NULL,
            WorkEmail VARCHAR(32) NOT NULL,
            title VARCHAR(32) NOT NULL,
            Date DATE NOT NULL,
            StartTime TIME NOT NULL,
            EndTime TIME NOT NULL,
            eventType TEXT NOT NULL,
            FOREIGN KEY (EmployeeID) REFERENCES Employee(EmployeeID)
            )`);
            db.run(`CREATE TABLE IF NOT EXISTS LeaveRequests (
                LeaveID INTEGER PRIMARY KEY AUTOINCREMENT,
                EmployeeID INTEGER NOT NULL,
                FromDate DATE NOT NULL,
                ToDate DATE NOT NULL,
                FromTime TIME NOT NULL,
                ToTime TIME NOT NULL,
                LeaveType TEXT NOT NULL,
                Reason TEXT NOT NULL,
                Status TEXT DEFAULT 'Pending', -- Pending, Approved, Rejected
                AppliedOn TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (EmployeeID) REFERENCES Employee(EmployeeID)
            )`);


        const adminEmail = process.env.ADMIN_EMAIL;
        const adminPassword = process.env.ADMIN_PASSWORD;
        const Id = 2401
        const EmployeeID = `GTS${Id}`
        const adminFname = "Ad"
        const adminlname = "min"
        const adminFullName = `${adminFname+adminlname}`;
        const admindesgination = "Founder and CEO";
        const adminCompany = "HRM";
        const adminstatus = "Active"
        const adminGender = "Male";
        const adminDateOfBirth = "1970-01-01";
        const adminCountry = "India";
        const adminAboutYourself = "Admin of the HRM platform";

        if (!adminPassword) {
            console.error("Admin password is not set in the environment variables");
            process.exit(1);
        }

        db.get(`SELECT * FROM Employee WHERE WorkEmail = ?`, [adminEmail], async (err, row) => {
            if (err) {
                console.error("Database retrieval error:", err);
            } else if (!row) {
                const hashedPassword = await bcrypt.hash(adminPassword, 8);
                const insertAdminQuery = `INSERT INTO Employee (EmployeeID,FirstName,LastName,FullName, WorkEmail, Role, Company,designation, Gender, DateOfBirth, Country, About_Yourself, Password,status) VALUES (?, ?, ?,?,? ,'Admin', ?, ?, ?, ?, ?,?, ?,?)`;
                db.run(insertAdminQuery, [EmployeeID,adminFname,adminlname,adminFullName, adminEmail, adminCompany,admindesgination, adminGender, adminDateOfBirth, adminCountry, adminAboutYourself, hashedPassword,adminstatus], (err) => {
                    if (err) {
                        console.error("Error inserting admin user:", err);
                    } else {
                        console.log("Admin user inserted successfully");
                    }
                });
            } else {
                console.log("Admin user already exists");
            }
        });
    }
});

db.run('PRAGMA foreign_keys = ON'); // foreign key ON

//mail transport and service,user and passkey used from env file
const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
});

// random password genterator
const generateRandomPassword = () => {
    return Math.random().toString(36).slice(-8); 
};

// Middleware to authorize based on role
function authorizeRole(requiredRoles = []) {
    return (req, res, next) => {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ error: 'Unauthorized' });
        }
        const token = authHeader.split(' ')[1];
        try {
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            if (!decoded.role) {
                return res.status(403).json({ error: 'Forbidden: No role found in token' });
            }
            if (!requiredRoles.includes(decoded.role)) {
                return res.status(403).json({ error: `Forbidden: Requires one of the roles ${requiredRoles.join(', ')}` });
            }

            req.user = decoded;
            next();
        } catch (err) {
            return res.status(401).json({ error: 'Unauthorized: Invalid token' });
        }
    };
}



//signup API
app.post("/signup", async (req, res) => {
    const { fullname, email, company,gender,dateofbirth, country, Aboutyourself } = req.body;

    if (!fullname || !email || !company || !gender || !dateofbirth || !country || !Aboutyourself) {
        return res.status(400).json({ message: "All fields are required" });
    }

    const randomPassword = generateRandomPassword();

    try {
        const hashedPassword = await bcrypt.hash(randomPassword, 8);
        const EmployeeID = generateEmployeeId()

        const insertQuery = `INSERT INTO Employee (EmployeeID,FullName, WorkEmail, Company,Gender, DateOfBirth, Country, About_Yourself, Password) VALUES (?,?, ?, ?,?,?, ?, ?, ?)`;

        db.run(insertQuery, [EmployeeID,fullname, email, company,gender, dateofbirth, country, Aboutyourself, hashedPassword], async function (err) {
            if (err) {
                console.error("Database insertion error:", err);
                return res.status(500).json({ message: "Error during signup" });
            }

            // Send Email
            const mailOptions = {
                from: process.env.EMAIL_USER,
                to: email,
                subject: "Welcome to HRM platform",
                html: `
    <div style="font-family: Arial, sans-serif; padding: 20px; background: #f9f9f9; border-radius: 8px; max-width: 600px; margin: auto; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);">
        <div style="text-align: center; margin-bottom: 20px;">
            <img src="https://static.vecteezy.com/system/resources/previews/007/263/716/non_2x/hrm-letter-logo-design-on-white-background-hrm-creative-initials-letter-logo-concept-hrm-letter-design-vector.jpg" 
                alt="Welcome Image" 
                style="max-width: 100px; height: auto; border-radius: 50%;" />
        </div>
        <p style="font-size: 18px; color: #333; text-align: center; font-weight: bold; margin: 0;">
            Welcome to the HRM Platform!
        </p>
        <p style="font-size: 16px; color: #555; text-align: center; margin:10px 75% 10px 0px;">
            Dear <strong>${fullname}</strong>,
        </p>
        <p style="font-size: 14px; line-height: 1.6; color: #666; text-align: justify;">
            We are thrilled to have you on board. Below are your login credentials:
        </p>
        <div style="background: #f1f1f1; padding: 15px; border-radius: 5px; margin: 20px 0; font-size: 14px;">
            <p style="margin: 0;"><strong>Username:</strong> ${email}</p>
            <p style="margin: 0;"><strong>Password:</strong> ${randomPassword}</p>
        </div>
        <p style="font-size: 14px; color: #666; text-align: justify; margin-bottom: 20px;">
            Please log in and change your password as soon as possible for enhanced security.
        </p>
        <div style="text-align: center; margin-top: 20px;">
            <a href="http://localhost:3000/" 
               style="display: inline-block; padding: 10px 20px; background: #4CAF50; color: #fff; text-decoration: none; font-size: 16px; border-radius: 5px; font-weight: bold;">
                Login to HRM Platform
            </a>
        </div>
        <p style="font-size: 14px; color: #999; text-align: center; margin-top: 20px;">
            Best regards,<br>
            <strong>The HRM Platform Team</strong>
        </p>
    </div>
`

            };

            try {
                const info = await transporter.sendMail(mailOptions);
                console.log("Email sent successfully:", info.response);
                res.status(201).json({ message: "Signup successful, email sent!" });
            } catch (emailError) {
                console.error("Error sending email:", emailError);
                res.status(500).json({ message: "Signup successful, but email sending failed" });
            }
        });
    } catch (hashError) {
        console.error("Error hashing password:", hashError);
        res.status(500).json({ message: "Error during signup" });
    }
});

// login API
app.post("/login", async (req, res) => {
    const { email, EmployeeID, password } = req.body;

    if ((!email && !EmployeeID) || !password) {
        return res.status(400).json({ message: "Email or EmployeeID and password are required" });
    }

    try {
        const query = `SELECT * FROM Employee WHERE WorkEmail = ? OR EmployeeID = ?`;
        db.get(query, [email || EmployeeID, email || EmployeeID], async (err, user) => {
            if (err) {
                console.error("Database error:", err);
                return res.status(500).json({ message: "Internal server error" });
            }

            if (!user) {
                return res.status(401).json({ message: "Invalid email or EmployeeID" });
            }

            const isPasswordValid = await bcrypt.compare(password, user.Password);
            if (!isPasswordValid) {
                return res.status(401).json({ message: "Invalid password" });
            }
            const currentTimeandDate = new Date();
            const currentDate = currentTimeandDate.toLocaleDateString();

            const currentTime = currentTimeandDate.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });

            const onTimeStartHours = 14; // Start of workday
            const lateCutoffHours = 14; // Late cutoff (9:30 AM)
            const lateCutoffMinutes = 30;
            const endOfDayHours = 18; // End of workday
            const endOfDayMinutes = 0;

            let ArrivalStatus = '';
            let LeaveStatus = "";
            let EffectiveHours = "";
            let GrossHours = "";
            let Log = "";

            const currentDay = currentTimeandDate.getDay(); // 0 = Sunday, 6 = Saturday

            if (currentDay === 0 || currentDay === 6) {
                Log = "EL";
            } else if (
                (currentTimeandDate.getHours() === onTimeStartHours &&
                    currentTimeandDate.getMinutes() >= 0 &&
                    currentTimeandDate.getMinutes() <= 15)
            ) {
                ArrivalStatus = "On Time";
                LeaveStatus = "No";
                EffectiveHours = "9:00 Hrs";
                GrossHours = "0:00 Hrs";
                Log = "Yes";
            } else if (
                (currentTimeandDate.getHours() === onTimeStartHours &&
                    currentTimeandDate.getMinutes() > 15 &&
                    currentTimeandDate.getMinutes() <= 30)
            ) {
                const minutesLate = currentTimeandDate.getMinutes() - 15;
                ArrivalStatus = `${minutesLate} minute late`;
                LeaveStatus = "No";
                EffectiveHours = "9:00 Hrs";
                GrossHours = "9:00 Hrs";
                Log = "No";
            } else if (
                currentTimeandDate.getHours() > endOfDayHours ||
                (currentTimeandDate.getHours() === endOfDayHours &&
                    currentTimeandDate.getMinutes() > endOfDayMinutes)
            ) {
                ArrivalStatus = "-";
                LeaveStatus = "Yes";
                EffectiveHours = "0:00 Hrs";
                GrossHours = "0:00 Hrs";
                Log = "EL";
            } else {
                ArrivalStatus = "-";
                LeaveStatus = "No";
                EffectiveHours = "0:00 Hrs";
                GrossHours = "0:00 Hrs";
                Log = "WH";
            } 
            const insertQuery = `INSERT INTO AttendanceLog(EmployeeID,WorkEmail, LogDate, LogTime, EffectiveHours, GrossHours, ArrivalStatus, LeaveStatus, Logstatus) VALUES (?, ?, ?, ?,?, ?, ?, ?, ?)`;
            db.run(
                insertQuery,
                [
                    user.EmployeeID,
                    user.WorkEmail,
                    currentDate,
                    currentTime,
                    EffectiveHours,
                    GrossHours,
                    ArrivalStatus,
                    LeaveStatus,
                    Log,
                ],
                (err) => {
                    if (err) {
                        console.error("Database error during attendance log insert:", err);
                    }
                }
            );

            const token = jwt.sign({id: user.EmployeeID,email: user.WorkEmail,issuedAt: currentTime,role: user.Role,},process.env.JWT_SECRET,{ expiresIn: "1h" });


            return res.status(200).json({
                user: {
                    fullname: user.FullName,
                    email: user.WorkEmail,
                    company: user.Company,
                    logDate: currentDate,
                    logTime: currentTime,
                    message: "Login successful",
                    role: user.Role,
                    desgination: user.designation,
                    token: token,


                },
            });
        });
    } catch (error) {
        console.error("Error during login:", error);
        return res.status(500).json({ message: "Internal server error" });
    }
});

//logout API
app.post('/logout', authorizeRole(['Admin', 'Employee']), (req, res) => {
    const usermail = req.user.email;
    const currentTimeandDate = new Date();
    const currentDate = currentTimeandDate.toLocaleDateString();
    const currentTime = currentTimeandDate.toLocaleTimeString();

    const query = `SELECT LogTime, ArrivalStatus FROM AttendanceLog WHERE WorkEmail = ? AND LogDate = ? AND Logstatus = 'Yes'`;
    db.get(query, [usermail, currentDate], (err, row) => {
        if (err) {
            console.error("Database retrieval error:", err);
            return res.status(500).json({ message: "Error fetching login time" });
        }

        if (!row) {
            return res.status(404).json({ message: "Login record not found for today" });
        }

        const loginTime = new Date(`${currentDate} ${row.LogTime}`);
        console.log(row.logTime)
        const logoutTime = new Date(`${currentDate} ${currentTime}`);
        const effectiveHours = ((logoutTime - loginTime) / (1000 * 60 * 60)).toFixed(2);

        console.log("logintime",loginTime)
        console.log("logoutime",logoutTime)
        console.log(effectiveHours)


        let leaveStatus = 'No';
        let arrivalStatus = row.ArrivalStatus;
        let grossHours = "9:00 Hrs";
        let log = "No";

        if (effectiveHours >= 9) {
            leaveStatus = 'Yes';
            log = "Yes";
        } else if (arrivalStatus.includes("minute late")) {
            const minutesLate = parseInt(arrivalStatus.split(" ")[0]);
            arrivalStatus = `${minutesLate} minute late`;
            grossHours = "9:00 Hrs";
        } else if (arrivalStatus === "On Time") {
            arrivalStatus = "On Time";
            grossHours = "9:00 Hrs";
        }

        const updateQuery = `UPDATE AttendanceLog SET LogTime = ?, EffectiveHours = ?, LeaveStatus = ?, ArrivalStatus = ?, GrossHours = ?, Logstatus = 'No' WHERE WorkEmail = ? AND LogDate = ? AND Logstatus = 'Yes'`;
        db.run(updateQuery, [currentTime, `${effectiveHours} Hrs`, leaveStatus, arrivalStatus, grossHours, usermail, currentDate], function (err) {
            if (err) {
                console.error("Database update error:", err);
                return res.status(500).json({ message: "Failed to update logout time" });
            }

            return res.status(200).json({ message: "Logout successful", effectiveHours: `${effectiveHours} Hrs` });
        });
    });
});

//Forgot password API
app.post('/forgotpassword', async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ message: "Email is required" });
    }

    const randomPassword = generateRandomPassword();

    try {
        const hashedPassword = await bcrypt.hash(randomPassword, 8);

        const checkQuery = `SELECT * FROM Employee WHERE WorkEmail = ?`;
        db.get(checkQuery, [email], (err, row) => {
            if (err) {
                console.error("Error checking email:", err);
                return res.status(500).json({ message: "An error occurred while checking the email" });
            }

            if (!row) {
                return res.status(404).json({ message: "Email not found" });
            }

            const updateQuery = `UPDATE Employee SET Password = ? WHERE WorkEmail = ?`;
            db.run(updateQuery, [hashedPassword, email], function (err) {
                if (err) {
                    console.error("Database update error:", err);
                    return res.status(500).json({ message: "Failed to update password" });
                }
                res.status(200).json({ message: "Password has been reset successfully" });
                const mailOptions = {
                    from: process.env.EMAIL_USER,
                    to: email,
                    subject: "Password Reset for HRM Platform",
                    html: `
                        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 20px auto; padding: 20px; border-radius: 8px; box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1); background-color: #f9f9f9;">
                            <div style="text-align: center; margin-bottom: 20px;">
                                <img src="https://static.vecteezy.com/system/resources/previews/007/263/716/non_2x/hrm-letter-logo-design-on-white-background-hrm-creative-initials-letter-logo-concept-hrm-letter-design-vector.jpg" 
                                    alt="HRM Platform Logo" 
                                    style="max-width: 100px; height: auto; border-radius: 50%; margin-bottom: 10px;" />
                                <h2 style="color: #333;">Password Reset Successful</h2>
                            </div>
                            <div style="color: #555; line-height: 1.6;">
                                <p>Dear <strong>Employee</strong>,</p>
                                <p>Your password for the HRM Platform has been successfully reset. Please use the following temporary password to log in:</p>
                                <div style="text-align: center; margin: 20px 0; padding: 10px; background-color: #e8f4fc; color: #007bff; font-weight: bold; border-radius: 5px;">
                                    ${randomPassword}
                                </div>
                                <p>We recommend changing your password immediately after logging in for security purposes.</p>
                                <p>If you did not request this password reset, please contact our support team at <a href="mailto:support@hrmplatform.com" style="color: #007bff; text-decoration: none;">support@hrmplatform.com</a>.</p>
                            </div>
                            <div style="margin-top: 30px; text-align: center;">
                                <a href="https://hrmplatform.com/login" 
                                style="display: inline-block; padding: 10px 20px; background-color: #007bff; color: #fff; text-decoration: none; border-radius: 5px; font-size: 16px;">
                                    Log In
                                </a>
                            </div>
                            <footer style="margin-top: 40px; text-align: center; font-size: 12px; color: #aaa;">
                                <p>© 2025 HRM Platform. All rights reserved.</p>
                            </footer>
                        </div>
                    `
                };

                transporter.sendMail(mailOptions, (error, info) => {
                    if (error) {
                        console.error("Error sending email:", error);
                    } else {
                        console.log("Password reset email sent:", info.response);
                    }
                });
            });
        });
    } catch (err) {
        console.error("Unexpected error:", err);
        res.status(500).json({ message: "An unexpected error occurred" });
    }
});



//attendance log fetch

app.get('/logs',authorizeRole('Employee'),(req,res) =>{
    const usermail = req.user.email;
    const query = `SELECT * FROM AttendanceLog WHERE WorkEmail = ? ORDER BY AttendanceLogID DESC `;

    db.all(query,[usermail],(err,row) =>{
        if(err){
            return res.status(500).json({ message: "Error fetching attendance data" });
        }
        res.status(200).json({ attendanceLogStatus: row });

    })

})

app.get('/request',authorizeRole('Employee'),(req,res) =>{
    const usermail = req.user.email;
    const query = `SELECT * FROM AttendanceLog WHERE WorkEmail = ? and Logstatus = "No"`;

    db.all(query,[usermail],(err,row) =>{
        if(err){
            return res.status(500).json({message:"Error Fetech attendance data"})
        }
        res.status(200).json({attendancerquest:row})

    })
})

app.get("/listemployee", authorizeRole(['Admin']), (req, res) => {
    const query = `SELECT EmployeeID, FullName, WorkEmail, Role, designation, phone,status,startdate, Company, Gender, DateOfBirth, Address, City, State, Country, PinCode, About_Yourself FROM Employee`;

    db.all(query, [], (err, rows) => {
        if (err) {
            console.error("Database retrieval error:", err);
            return res.status(500).json({ message: "Error fetching employee data" });
        }

        res.status(200).json({ data: rows });
    });
});

//Fetch employee using middleware auth
app.get("/employee", authorizeRole(['Admin','Employee']), (req, res) => {
    const usermail = req.user.email; 
    const query = `SELECT * FROM Employee WHERE WorkEmail = ?`;

    db.get(query, [usermail], (err, row) => {
        if (err) {
            console.error("Database retrieval error:", err);
            return res.status(500).json({ message: "Error fetching employee data" });
        }

        if (!row) {
            return res.status(404).json({ message: "Employee not found" });
        }
        const {Password, ...filteredRow } = row;

        res.status(200).json({ employee: filteredRow });
    });
});


app.post("/events", authorizeRole(["Admin",'Employee']), (req, res) => {
    const { title, date, startTime, endTime, type } = req.body; // Ensure the field name matches the client expectation
    const usermail = req.user.email;
    const employeeid = req.user.id;

    console.log('Received event data:', req.body);
    console.log(usermail);
    console.log(employeeid);

    if (!usermail || !title || !date || !startTime || !endTime || !type) { // Fix the condition to check for type
        return res.status(400).json({ error: "All fields are required" });
    }

    const query = `INSERT INTO Events(EmployeeID, WorkEmail, title, Date, StartTime, EndTime, eventType) VALUES (?, ?, ?, ?, ?, ?, ?)`;
    db.run(query, [employeeid, usermail, title, date, startTime, endTime, type], function (err) {
        if (err) {
            console.error("Database insertion error:", err.message);
            return res.status(500).json({ error: "Error while inserting event" });
        }

        return res.status(201).json({ message: "Event successfully inserted", eventId: this.lastID });
    });
});

app.get('/events', authorizeRole(["Admin",'Employee']), (req, res) => {
    const usermail = req.user.email;
    console.log(usermail);
    const query = `SELECT * FROM Events WHERE WorkEmail = ?`;

    db.all(query, [usermail], (err, rows) => {
        if (err) {
            console.error("Error while fetching events:", err);
            return res.status(500).json({ error: "Error while fetching events" });
        }
        return res.status(200).json({ events: rows });
    });
});

app.delete('/events/:id', authorizeRole(["Admin",'Employee']), (req, res) => {
    const usermail = req.user.email; 
    const eventId = req.params.id; 

    const query = `DELETE FROM Events WHERE WorkEmail = ? AND EventsID = ?`;

    db.run(query, [usermail, eventId], function (err) {
        if (err) {
            return res.status(500).json({ error: "Error while deleting event" });
        }

        if (this.changes === 0) {
            return res.status(404).json({ message: "Event not found or not authorized to delete" });
        }

        return res.status(200).json({ message: "Event deleted successfully" });
    });
});

// Change Password API
app.post('/changepassword', authorizeRole(["Admin","Employee"]), async (req, res) => {
    const { oldPassword, newPassword } = req.body;
    const usermail = req.user.email;

    if (!oldPassword || !newPassword) {
        return res.status(400).json({ message: "Old password and new password are required" });
    }

    if (oldPassword === newPassword) {
        return res.status(400).json({ message: "New password cannot be the same as the old password" });
    }

    try {
        const query = `SELECT Password FROM Employee WHERE WorkEmail = ?`;
        db.get(query, [usermail], async (err, user) => {
            if (err) {
                console.error("Database error:", err);
                return res.status(500).json({ message: "Internal server error" });
            }

            if (!user) {
                return res.status(404).json({ message: "User not found" });
            }

            const isPasswordValid = await bcrypt.compare(oldPassword, user.Password);
            if (!isPasswordValid) {
                return res.status(401).json({ message: "Old password is incorrect" });
            }

            const hashedNewPassword = await bcrypt.hash(newPassword, 8);
            const updateQuery = `UPDATE Employee SET Password = ? WHERE WorkEmail = ?`;
            db.run(updateQuery, [hashedNewPassword, usermail], function (err) {
                if (err) {
                    console.error("Database update error:", err);
                    return res.status(500).json({ message: "Failed to update password" });
                }

                return res.status(200).json({ message: "Password changed successfully" });
            });
        });
    } catch (error) {
        console.error("Unexpected error:", error);
        return res.status(500).json({ message: "An unexpected error occurred" });
    }
});



// Fetch employee details using EmployeeID
app.get('/employee/:employeeID', authorizeRole(['Admin']), (req, res) => {
    const employeeID = req.params.employeeID;

    const query = `
        SELECT EmployeeID, FullName, FirstName, LastName, WorkEmail, Role, designation, phone, startdate,status, Company, Address, City, State, Country, PinCode, Gender, DateOfBirth, About_Yourself
        FROM Employee
        WHERE EmployeeID = ?
    `;

    db.get(query, [employeeID], (err, row) => {
        if (err) {
            console.error("Database retrieval error:", err);
            return res.status(500).json({ message: "Error fetching employee data" });
        }

        if (!row) {
            return res.status(404).json({ message: "Employee not found" });
        }

        res.status(200).json({ data: row });
    });
});

// Fetch attendance logs by employee ID for Admin
app.get('/attendance/:employeeID', authorizeRole(['Admin']), (req, res) => {
    const employeeID = req.params.employeeID;

    const query = `
        SELECT *
        FROM AttendanceLog a
        WHERE a.WorkEmail = (SELECT WorkEmail FROM Employee WHERE EmployeeID = ?)
        ORDER BY a.Logdate DESC
    `;

    db.all(query, [employeeID], (err, rows) => {
        if (err) {
            console.error("Database retrieval error:", err);
            return res.status(500).json({ message: "Error fetching attendance logs" });
        }

        if (rows.length === 0) {
            return res.status(404).json({ message: "No attendance logs found for this employee" });
        }

        res.status(200).json({ attendanceLogs: rows });
    });
});

// Register Employee API
app.post("/registeremployee", authorizeRole('Admin'), async (req, res) => {
    const { fullname, firstName, lastName, email, phone, dateOfBirth, department, position, startDate, streetAddress, city, state, zipCode, country, gender, company } = req.body;

    if (!fullname || !firstName || !lastName || !email || !phone || !dateOfBirth || !department || !position || !startDate || !streetAddress || !city || !state || !zipCode || !country || !gender || !company) {
        console.log("All fields are required");
        return res.status(400).json({ message: "All fields are required" });
    }

    db.get("SELECT EmployeeID FROM Employee ORDER BY EmployeeID DESC LIMIT 1", async (err, row) => {
        if (err) {
            console.error("Error fetching last EmployeeID:", err);
            return res.status(500).json({ message: "Database error" });
        }

        let prefix = row.EmployeeID.match(/^[A-Za-z]+/)[0]; 
        let number = row.EmployeeID.match(/\d+$/)[0]; // "241201"
        let newNumber = String(parseInt(number, 10) + 1).padStart(number.length, '0');
        let EmployeeID = prefix + newNumber;



        const randomPassword = generateRandomPassword();
        const hashedPassword = await bcrypt.hash(randomPassword, 8);
        const about = `${fullname} has joined as a ${position}`;

        const insertQuery = `INSERT INTO Employee (EmployeeID, FullName, FirstName, LastName, WorkEmail, Role, designation, phone, startdate, Company, Address, City, State, PinCode, Country, Gender, DateOfBirth, About_Yourself, Password, status) 
                             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,?, "Active")`;

        db.run(insertQuery, [EmployeeID, fullname, firstName, lastName, email, department, position, phone, startDate, company, streetAddress, city, state, zipCode, country, gender, dateOfBirth, about, hashedPassword], function (err) {
            if (err) {
                console.error("Database insertion error:", err);
                return res.status(500).json({ message: "Error during employee registration" });
            }

            console.log("Employee registered successfully with ID:", EmployeeID);

            // onboarding email
            const onboardingMailOptions = {
                from: process.env.EMAIL_USER,
                to: email,
                subject: "Welcome to the HRM",
                html: `
                    <div style="font-family: Arial, sans-serif; padding: 20px; max-width: 600px; margin: auto; border: 1px solid #ddd; border-radius: 0px; box-shadow: 0px 4px 8px rgba(0, 0, 0, 0.1); background: #fffff;">

                        <div >
                            
                            <img style="text-align: left; margin-bottom: 20px; max-width: 120px;" src="data:image/jpeg;base64,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" alt="Company Logo">
                        </div>

                        <p style="font-size: 20px; color: #ea6f33; text-align: center; font-weight: bold; margin: 0;">
                            Welcome!
                        </p>

                        <p style="font-size: 16px; color: #333; text-align: left; margin: 25px 0;">
                            Hi <strong>${fullname}</strong>,
                        </p>

                        <p style="font-size: 14px; line-height: 1.6; color: #555; text-align: justify;">
                            We are delighted to welcome you aboard! Your skills and talents are exactly what we need to take our projects to the next level. We can’t wait to see the impact you’ll make!
                            As part of your onboarding, we've outlined the key steps to get you started smoothly. Keep an eye on your inbox for further details, and don’t hesitate to reach out if you have any questions.
                        </p>
                        <p style="font-size: 16px; color: #ea6f33; text-align: center; font-weight: bold; margin-bottom: 20px; margin-top:50px;">
                            Best regards,<br>
                            The HRM Platform Team
                        </p>

                        <!-- Footer -->
                        <div style="border-top:1px solid #ea6f33; margin-top: 20px; padding-top: 15px; text-align: center; font-size: 12px; color: #777;">
                            <p style="margin: 5px 0;">Follow us: 
                                <a href="https://twitter.com" style="text-decoration: none; color: #ea6f33; font-weight: bold;">Website</a> | 
                                <a href="https://linkedin.com" style="text-decoration: none; color: #ea6f33; font-weight: bold;">LinkedIn</a>
                            </p>
                            <p style="margin: 5px 0;">&copy; 2024 HRM Platform. All rights reserved.</p>
                        </div>

                        <!-- Responsive Design -->
                        <style>
                            @media screen and (max-width: 480px) {
                                div {
                                    padding: 15px;
                                }
                                p {
                                    font-size: 13px !important;
                                }
                                img {
                                    max-width: 100px;
                                    margin-left:50px;
                                }
                            }
                        </style>
                    </div>
                `
            };

            transporter.sendMail(onboardingMailOptions, (error, info) => {
                if (error) {
                    console.error("Error sending onboarding email:", error);
                } else {
                    console.log("Onboarding email sent:", info.response);
                }
            });

            //login credentials email after 5 minutes
            setTimeout(() => {
                const credentialsMailOptions = {
                    from: process.env.EMAIL_USER,
                    to: email,
                    subject: "Onboarding Complete.You're officially part of the HRM Platform!",
                    html: `
                        <div style="font-family: Arial, sans-serif; padding: 20px; background: #f9f9f9; border-radius: 8px; max-width: 600px; margin: auto; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);">
                            <div style="text-align: center; margin-bottom: 20px;">
                                <img src="https://static.vecteezy.com/system/resources/previews/007/263/716/non_2x/hrm-letter-logo-design-on-white-background-hrm-creative-initials-letter-logo-concept-hrm-letter-design-vector.jpg" 
                                    alt="Credentials Image" 
                                    style="max-width: 100px; height: auto; border-radius: 50%;" />
                            </div>
                            <p style="font-size: 18px; color: #333; text-align: center; font-weight: bold; margin: 0;">
                                You are now an official member of the HRM Platform!
                            </p>
                            <p style="font-size: 16px; color: #555; text-align: center; margin:10px 75% 10px 0px;">
                                Dear <strong>${fullname}</strong>,
                            </p>
                            <p style="font-size: 14px; line-height: 1.6; color: #666; text-align: justify;">
                                Below are your login credentials for the HRM platform:
                            </p>
                            <div style="background: #f1f1f1; padding: 15px; border-radius: 5px; margin: 20px 0; font-size: 14px;">
                                <p style="margin: 0;"><strong>Username:</strong> ${email}</p>
                                <p style="margin: 0;"><strong>Password:</strong> ${randomPassword}</p>
                            </div>
                            <p style="font-size: 14px; color: #666; text-align: justify; margin-bottom: 20px;">
                                Please log in and change your password as soon as possible for enhanced security.
                            </p>
                            <div style="text-align: center; margin-top: 20px;">
                                <a href="http://localhost:3000/" 
                                   style="display: inline-block; padding: 10px 20px; background: #4CAF50; color: #fff; text-decoration: none; font-size: 16px; border-radius: 5px; font-weight: bold;">
                                    Login to HRM Platform
                                </a>
                            </div>
                            <p style="font-size: 14px; color: #999; text-align: center; margin-top: 20px;">
                                Best regards,<br>
                                <strong>The HRM Platform Team</strong>
                            </p>
                        </div>
                    `
                };

                transporter.sendMail(credentialsMailOptions, (error, info) => {
                    if (error) {
                        console.error("Error sending credentials email:", error);
                    } else {
                        console.log("Credentials email sent:", info.response);
                    }
                });
            }, 30 * 60 * 1000); // 30 minutes 

            return res.status(201).json({ message: "Employee registered successfully", EmployeeID: EmployeeID });
        });
    });
});



//update empolyee API
app.put("/employee/:id", authorizeRole(['Admin']), (req, res) => {
    const employeeID = req.params.id;
    const { FullName, FirstName, LastName, WorkEmail, Role, designation, phone, startdate, Company, Address, City, State, PinCode, Country, Gender, DateOfBirth, About_Yourself, status, Enddate } = req.body;
    console.log(req.body);

    const updateQuery = `
        UPDATE Employee
        SET FullName = ?, FirstName = ?, LastName = ?, WorkEmail = ?, Role = ?, designation = ?, phone = ?, startdate = ?, Company = ?, Address = ?, City = ?, State = ?, PinCode = ?, Country = ?, Gender = ?, DateOfBirth = ?, About_Yourself = ?, status = ?, Enddate = ?
        WHERE EmployeeID = ?
    `;

    db.run(updateQuery, [FullName, FirstName, LastName, WorkEmail, Role, designation, phone, startdate, Company, Address, City, State, PinCode, Country, Gender, DateOfBirth, About_Yourself, status, Enddate, employeeID], function (err) {
        if (err) {
            console.error("Database update error:", err);
            return res.status(500).json({ message: "Error updating employee details" });
        }

        if (this.changes === 0) {
            return res.status(404).json({ message: "Employee not found" });
        }

        return res.status(200).json({ message: "Employee details updated successfully" });
    });
});

app.put("/employee-status/:id",authorizeRole(['Admin']),(req,res) =>{
    const employeeID = req.params.id;
    const{status,Enddate} = req.body

    const updateQuery =  `UPDATE Employee SET status = ?,Enddate = ? WHERE EmployeeID = ?`;

    db.run(updateQuery,[status,Enddate,employeeID] ,function(err){
        if(err){
            console.error("Database update error:",err);
            return res.status(500).json({message:"Error updating status of empolyee"})
        }
        if (this.changes === 0) {
            return res.status(404).json({ message: "Employee not found" });
        }

        return res.status(200).json({ message: "Employee status updated successfully" });
    })
})

const MAX_LEAVE_DAYS = 30;

app.post("/apply",authorizeRole(["Employee"]) , (req, res) => {
    try {
        const EmployeeID = req.user.id; // Extract EmployeeID from JWT Token
        const { FromDate, ToDate, FromTime, ToTime, LeaveType, Reason } = req.body;
        console.log(req.body);

        const fromDate = new Date(FromDate);
        const toDate = new Date(ToDate);
        const today = new Date();

        const leaveDays = Math.ceil((toDate - fromDate) / (1000 * 60 * 60 * 24)) + 1;

        const leaveCountQuery = `SELECT SUM(JULIANDAY(ToDate) - JULIANDAY(FromDate) + 1) AS TotalLeaves 
                                 FROM LeaveRequests WHERE EmployeeID = ? AND Status = 'Approved'`;
        db.get(leaveCountQuery, [EmployeeID], (err, row) => {
            if (err) {
                return res.status(500).json({ message: "Database error", error: err.message });
            }

            const totalUsedLeaves = row?.TotalLeaves || 0;
            if (totalUsedLeaves + leaveDays > MAX_LEAVE_DAYS) {
                return res.status(400).json({ message: `Leave quota exceeded! You have ${MAX_LEAVE_DAYS - totalUsedLeaves} days left.` });
            }

            const overlapQuery = `SELECT * FROM LeaveRequests WHERE EmployeeID = ? 
                                  AND (DATE(FromDate) <= DATE(?) AND DATE(ToDate) >= DATE(?))`;
            db.get(overlapQuery, [EmployeeID, ToDate, FromDate], (err, existingLeave) => {
                if (err) {
                    return res.status(500).json({ message: "Database error", error: err.message });
                }

                if (existingLeave) {
                    return res.status(400).json({ message: "Leave request conflicts with existing leave period." });
                }
                // Insert leave request
                const insertQuery = `INSERT INTO LeaveRequests (EmployeeID, FromDate, ToDate, FromTime, ToTime, LeaveType, Reason, Status) 
                                     VALUES (?, ?, ?, ?, ?, ?, ?, 'Pending')`;
                db.run(insertQuery, [EmployeeID, FromDate, ToDate, FromTime, ToTime, LeaveType, Reason], function (err) {
                    if (err) {
                        return res.status(500).json({ message: "Failed to apply for leave", error: err.message });
                    }
                    res.status(201).json({ message: "Leave request submitted successfully", LeaveID: this.lastID, Status: "Pending" });
                });
            });
        });
    } catch (error) {
        res.status(500).json({ message: "Unexpected error occurred", error: error.message });
    }
});



// Total no of leaves applied by employee
app.get("/leaves",authorizeRole(["Employee"]) ,(req, res) => {
    const EmployeeID = req.user.id; // Get the employee ID from the JWT token

    db.all(`SELECT * FROM LeaveRequests WHERE EmployeeID = ?`, [EmployeeID], (err, rows) => {
        if (err) {
            console.error("Database error:", err);
            return res.status(500).json({ message: "Internal server error" });
        }
        return res.status(200).json({ data: rows });
    });
});


app.get("/leavescount",authorizeRole(["Employee"]) ,(req, res) => {
    const EmployeeID = req.user.id; 

    db.get(`SELECT SUM(JULIANDAY(ToDate) - JULIANDAY(FromDate) + 1) AS TotalLeaves FROM LeaveRequests WHERE EmployeeID = ?`, [EmployeeID], (err, row) => {
        if (err) {
            console.error("Database error:", err);
            return res.status(500).json({ message: "Internal server error" });
        }
        return res.status(200).json({ TotalLeaves: row.TotalLeaves || 0 });
    });
});

app.delete("/leaves",authorizeRole(["Employee"]) ,(req, res) => {
    const EmployeeID = req.user.id; 

    db.run(`DELETE FROM LeaveRequests WHERE EmployeeID = ?`, [EmployeeID], function (err) {
        if (err) {
            console.error("Database error:", err);
            return res.status(500).json({ message: "Internal server error" });
        }

        if (this.changes === 0) {
            return res.status(404).json({ message: "No leave requests found" });
        }

        return res.status(200).json({ message: "All leave requests deleted successfully" });
    });
});

app.post("/store-email", (req, res) => {
    const { subject, message, from_name, reply_to } = req.body;
    console.log(req.body)

    if (!subject || !message || !from_name || !reply_to) {
        return res.status(400).json({ message: "All fields are required" });
    }

    const insertQuery = `INSERT INTO Emails (Subject, Message, FromName, ReplyTo) VALUES (?, ?, ?, ?)`;
    db.run(insertQuery, [subject, message, from_name, reply_to], function (err) {
        if (err) {
            console.error("Database insertion error:", err);
            return res.status(500).json({ message: "Error storing email" });
        }

        return res.status(201).json({ message: "Email stored successfully", EmailID: this.lastID });
    });
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});

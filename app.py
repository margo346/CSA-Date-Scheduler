import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash
# from django.shortcuts import render
# from CSA.helpers import ProfilesModel

from helpers import apology, login_required

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///csa.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/datelog")
@login_required
def datelog():
    """Show a log of accepted dates"""
    accepted_dates = db.execute("SELECT * FROM dates WHERE friend_id = ? AND accepted = 1", session["user_id"])
    accepted_dates += db.execute("SELECT * FROM dates WHERE user_id = ? AND accepted = 1", session["user_id"])
    for accepted_date in accepted_dates:
        accepted_date["user_id"] = db.execute("SELECT name FROM profiles WHERE user_id = ?", accepted_date["user_id"])[0]["name"]
        accepted_date["friend_id"] = db.execute("SELECT name FROM profiles WHERE user_id = ?", accepted_date["friend_id"])[0]["name"]

    print(accepted_dates)

    return render_template("datelog.html", accepted_dates=accepted_dates)


@app.route("/")
@login_required
def home():
    """Show homepage"""
    name = db.execute("SELECT name FROM profiles WHERE user_id = ?", session["user_id"])[0]["name"]
    concentration = db.execute("SELECT concentration FROM profiles WHERE user_id = ?", session["user_id"])[0]["concentration"]
    classyear = db.execute("SELECT classyear FROM profiles WHERE user_id = ?", session["user_id"])[0]["classyear"]
    house = db.execute("SELECT house FROM profiles WHERE user_id = ?", session["user_id"])[0]["house"]
    email = db.execute("SELECT email FROM profiles WHERE user_id = ?", session["user_id"])[0]["email"]

    return render_template("home.html", name=name, concentration=concentration, classyear=classyear, house=house, email=email)


@app.route("/datescheduler", methods=["GET", "POST"])
@login_required
def datescheduler():
    """Propose dates with other users"""

    # When requested via POST, schedule the date as long as necessary conditions are met
    if request.method == "POST":

        # Require that the user input their name
        yourname = request.form.get("yourname")
        if not yourname:
            return apology ("must provide your name", 400)

        # Require that the user input a date for the date
        date = request.form.get("date")
        time = request.form.get("time")
        if not date or not time:
            return apology ("must propose a day and time for the date", 400)

        # Require that the user input a location
        location = request.form.get("location")
        if not location:
            return apology ("must propose a location for the date", 400)

        # Require that the user selects another user to invite
        friend_name = request.form.get("friend")
        if not friend_name:
            return apology ("must invite a friend in CSA", 400)
        rows = db.execute("SELECT * FROM profiles WHERE name LIKE ?", friend_name)
        if len(rows) != 1:
            return apology ("must provide a valid name of a CSA member", 400)

        # Run SQL query to propose the date!
        friend_id = rows[0]["user_id"]
        db.execute("INSERT INTO dates (name, user_id, friend_id, date, time, location) VALUES (?, ?, ?, ?, ?, ?)", yourname, session["user_id"], friend_id, date, time, location)

        flash("Date proposed!")

        return redirect("/")

    # When requested via GET, display form to propose a date
    if request.method == "GET":
        return render_template("datescheduler.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/search", methods=["GET", "POST"])
@login_required
def search():
    """Search for members based on information filters"""

    # When requested via POST, filter using the inputted information
    if request.method == "POST":
        name = request.form.get("name")
        classyear = request.form.get("classyear")
        concentration = request.form.get("concentration")
        house = request.form.get("house")

        query = "SELECT * FROM profiles WHERE 1"

        if name != "":
            query += " AND name LIKE " + "'" + name + "'"

        if classyear != "":
            query += " AND classyear = " + classyear

        if (concentration != "" and concentration != "All"):
            query += " AND concentration = " + "'" + concentration + "'"

        if (house != "" and house != "All"):
            query += " AND house = " + "'" + house + "'"

        query += ";"

        matched_profiles = db.execute(query)

        return render_template("searched.html", matched_profiles=matched_profiles)

    else:
        return render_template("search.html")


@app.route("/notifications", methods=["GET", "POST"])
def notifications():
    """Notify user of date invites"""

    # User reached form via POST (as via clicking a button)
    if request.method == "POST":

        old_invites = db.execute("SELECT * FROM dates WHERE friend_id = ? AND accepted = 0", session["user_id"])

        if request.form.get("accept"):
            db.execute("UPDATE dates SET accepted = 1 WHERE id = ?", old_invites[0]["id"])
            db.execute("UPDATE profiles SET num_dates = num_dates + 1 WHERE id = ?", session["user_id"])
            db.execute("UPDATE profiles SET num_dates = num_dates + 1 WHERE id = ?", old_invites[0]["user_id"])
            flash("Date accepted!")

        if request.form.get("defer"):
            db.execute("UPDATE dates SET accepted = 2 WHERE id = ?", old_invites[0]["id"])
            flash("Date deferred!")

        invites = db.execute("SELECT * FROM dates WHERE friend_id = ? AND accepted = 0", session["user_id"])
        total_invites = len(invites)
        total_dates = db.execute("SELECT * FROM dates WHERE accepted = 1 AND user_id = ?", session["user_id"])
        total_dates += db.execute("SELECT * FROM dates WHERE accepted = 1 AND friend_id = ?", session["user_id"])
        total_dates = len(total_dates)

        return render_template("notifications.html", invites=invites, total_invites=total_invites, total_dates=total_dates)

    # User reached page via GET (via link or redirect)
    else:
        invites = db.execute("SELECT name, date, time, location FROM dates WHERE friend_id = ? AND accepted = 0", session["user_id"])
        total_invites = len(invites)
        total_dates = db.execute("SELECT num_dates FROM profiles WHERE user_id = ?", session["user_id"])
        total_dates = total_dates[0]["num_dates"]

        return render_template("notifications.html", invites=invites, total_invites=total_invites, total_dates=total_dates)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Return an apology if any field is left blank
        if not username:
            return apology("must provide username", 400)
        if not password:
            return apology("must provide password", 400)
        if not confirmation:
            return apology("must provide confirmation", 400)

        # Return an apology if password and confirmation do not match
        if password != confirmation:
            return apology("passwords do not match", 400)

        # Returns an apology if username is already taken
        if len(db.execute("SELECT * FROM users WHERE username = ?", username)) != 0:
            return apology("username already exists", 400)

        name = request.form.get("name")
        classyear = int(request.form.get("classyear"))
        concentration = request.form.get("concentration")
        house = request.form.get("house")
        email = request.form.get("email")

        # Return an apology if any field is left blank
        if not name:
            return apology("must provide first and last name", 400)
        if not email:
            return apology("must provide Harvard College email", 400)
        if not classyear:
            return apology("must provide graduation year", 400)
        if not concentration:
            return apology("must provide concentration", 400)
        if not house:
            return apology("must provide house", 400)

        if classyear > 2026 or classyear < 2022:
            return apology("must provide a valid graduation year", 400)

        # If no errors, insert the user into users table
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, generate_password_hash(password))

        rows = db.execute("SELECT * FROM users WHERE username = ?", username)
        session["user_id"] = rows[0]["id"]

        # If no errors, insert the user information into the profiles table
        db.execute("INSERT INTO profiles (user_id, name, email, classyear, concentration, house) VALUES (?, ?, ?, ?, ?, ?)", session["user_id"], name, email, classyear, concentration, house)

        return redirect("/login")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/scoreboard", methods=["GET"])
@login_required
def scoreboard():
    """Display people with highes date scores"""

    topscorers = db.execute("SELECT name, classyear, num_dates FROM profiles ORDER BY num_dates DESC LIMIT 3")
    firstperson = topscorers[0]
    secondperson = topscorers[1]
    thirdperson = topscorers[2]

    return render_template("scoreboard.html", firstperson=firstperson, secondperson=secondperson, thirdperson=thirdperson)


# Allow the user to update their profile (the concentration and class year aspects only)
@app.route("/updateprofile", methods=["GET", "POST"])
@login_required
def updateprofile():
    """Update Profile"""

    if request.method == "POST":
        newclassyear = request.form.get("newclassyear")
        newconcentration = request.form.get("newconcentration")
        newhouse = request.form.get("newhouse")

        # Update user's information based on input
        if newclassyear != "":
            newclassyear = int(newclassyear)
            db.execute("UPDATE profiles SET classyear = ? WHERE user_id = ?", newclassyear, session["user_id"])

        if newhouse != None:
            db.execute("UPDATE profiles SET house = ? WHERE user_id = ?", newhouse, session["user_id"])

        if newconcentration != "No Change":
            db.execute("UPDATE profiles SET concentration = ? WHERE user_id = ?", newconcentration, session["user_id"])
        return redirect("/")

    if request.method == "GET":
        return render_template("update.html")
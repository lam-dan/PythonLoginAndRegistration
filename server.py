from flask import Flask, render_template, request, session, redirect, flash
from flask_bcrypt import Bcrypt
from mysqlconnection import connectToMySQL
import re
import copy

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9.+_-]+\.[a-zA-z]+$')

app=Flask(__name__)
app.secret_key = "ThisIsASecret"
bcrypt = Bcrypt(app)     # we are creating an object called bcrypt, 
                         # which is made by invoking the function Bcrypt with our app as an argument

@app.route("/")

def index():

	if "last_name" not in session:
		session["first_name"] = ""
		session["last_name"] = ""
		session["email"] = ""
		session["userid"] = ""

	return render_template ("index.html")

@app.route("/register", methods = ["POST"])

def logincheck():

	session.clear()

	#first name errors
	if len(request.form['first_name']) < 1:
		flash("This field is required", "flashfirstname")
	elif len(request.form['first_name']) < 2:
		session["first_name"] = request.form['first_name']
		flash("First name needs to be longer than two characters, and contain only text.","flashfirstname")
	if request.form['first_name'].isalpha() == False:
		flash("First name cannot contain numbers", "flashfirstname")

	#last name errors
	if len(request.form['last_name']) < 1:
		flash("This field is required", "flashlastname")
	elif len(request.form['last_name']) < 2:
		flash("Last name needs to be longer than two characters, and contain only text.", "flashlastname")
	if request.form['first_name'].isalpha() == False:
		flash("First name cannot contain numbers", "flashfirstname")

	#email errors
	if len(request.form['email']) < 1:
		flash("This field is required", "flashemail")
	elif not EMAIL_REGEX.match(request.form['email']):
		flash("Invalid Email Address", "flashemail")

	#check e-mail against database and returns count
	mysql = connectToMySQL("mydb")
	query = "select idUsers,emails from users where emails = %(emails)s;"
	data = {"emails":request.form["email"]}
	emailcheck = mysql.query_db(query,data)

	#password errors
	if len(request.form['password']) < 1:
		flash("This field is required", "flashpassword")
	elif len(request.form['password']) < 8:
		flash("Password name needs to be longer than eight characters", "flashpassword")

	#confirm password errors
	if len(request.form['confirmpassword']) < 1:
		flash("This field is required", "flashconfirmpassword")
	elif len(request.form['confirmpassword']) < 8:
		flash("Password name needs to be longer than eight characters", "flashconfirmpassword")
	elif request.form['password'] != request.form['confirmpassword']:
		flash("The passwords do not match.","flashpassword")

	# if emailcheck: <- checks if you get a result or not
	#if count of e-mails is less than 1 insert into table
	if len(emailcheck) < 1 and request.form['password'] == request.form['confirmpassword']:

		session["email"] = request.form["email"]
		session["first_name"] = request.form["first_name"]
		session["last_name"] = request.form["last_name"]

		pw_hash = bcrypt.generate_password_hash(request.form['password'])


		mysql = connectToMySQL('mydb')
		query2 = "insert into users (idUsers,first_name,last_name,emails,password,date_created,last_updated) values (idUsers,%(first_name)s, %(last_name)s,%(emails)s,%(password_hash)s,now(),now())"
		data2 = {
		"first_name": request.form["first_name"],
		"last_name": request.form["last_name"],
		"emails":request.form["email"],
		"password_hash": pw_hash
		}
		insertemail = mysql.query_db(query2,data2)
	else:
		flash("This email is already registered.", "flashemail")

			
	if '_flashes' in session.keys():
		return redirect("/")
	else:
		session['email'] = request.form['email']
		session['first_name'] = request.form['first_name']
		session['last_name'] = request.form['last_name']

		mysql = connectToMySQL("mydb")
		query = "select idUsers,emails from users where emails = %(emails)s;"
		data = {"emails":request.form["email"]}
		emailcheck = mysql.query_db(query,data)
		session['userid'] = emailcheck[0]['idUsers']

		flash("You've successly been registered.", "flashsuccess")
		return redirect("/success")

@app.route("/login", methods = ["POST"])

def login():

	mysql = connectToMySQL("mydb")
	query = "SELECT idUsers,emails,password,first_name FROM users WHERE emails = %(emails)s;"
	data = { "emails" : request.form["email"] }
	result = mysql.query_db(query, data)

	if result:
		if bcrypt.check_password_hash(result[0]['password'], request.form['password']):
		# if we get True after checking the password, we may put the user id in session
			session['userid'] = result[0]['idUsers']
			session["first_name"] = result[0]["first_name"]
			return redirect('/success')
	flash("This email login and password combination does not exist.","flashlogin")
	return redirect("/")

@app.route("/success")

def success():

	print(session["userid"])

	if session["userid"] == "":
		flash("You must be logged in to enter this website.", "flashlogout")
		return redirect ("/")
	else:
		return render_template("success.html", name = session["first_name"])

@app.route("/logout")

def logout():

	session.clear()
	print(session)
	flash("You have been logged out.","flashlogout")
	return redirect ("/")

if __name__ == "__main__":
	app.run(debug=True)
#Joana
from time import time
from flask import Flask, render_template, request, redirect, url_for, session, app, flash, make_response
from flask_mysqldb import MySQL
from datetime import timedelta
import MySQLdb.cursors
import re
import logging

#Pranawi
from flask_recaptcha import ReCaptcha
from flask_bootstrap import Bootstrap
import pyotp
from password_strength import PasswordPolicy
from password_strength import PasswordStats
#from flask_bcrypt import bcrypt
#from bcrypt import hashpw, gensalt, checkpw
#import bcrypt
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import mysql.connector as connection
import pandas as pd
from markupsafe import *

#Wei Shan
from tracemalloc import start
import random
import time
from flask_mail import Mail, Message
from twilio.rest import Client
import jwt

#additional pages
from tkinter import PhotoImage
from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_required, current_user, logout_user
from models import Notes, Message, Supplier, Product, BaseLog
from forms import EditUser, AddNotes, TicketForm, AddUser, AddProductForm, EmailForm,  AddSuppliersForm
from uuid import uuid4
import shelve
from datetime import datetime
from werkzeug.utils import secure_filename
import base64

import os
import shelve # Persistent storage
from datetime import datetime
from uuid import uuid4 # Unique key generator

app = Flask(__name__)
#1 make disconnect out page
#2 improve log file locations
#3 improve on others 
#4 integrate work with others
#5 finish up work

#Logging 
#%(levelname)s %(name)s :
#logging.basicConfig(filename='record.log', encoding='utf-8', filemode='w', level=logging.DEBUG, format=f'%(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')
#logging.warning('is when this event was logged.')
#trying to log in to database using logging

formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')

def setup_logger(name, log_file, level=logging.DEBUG):
    handler = logging.FileHandler(log_file)
    handler.setFormatter(formatter)

    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.addHandler(handler)

    return logger

#expiration date for login
@app.before_first_request
def make_Session_Permanent():
    
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=1)
    session.modified = True
    

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    return response

#Password Policies
policy = PasswordPolicy.from_names(
    length=8,  # min length: 8
    uppercase=1,  # need min. 2 uppercase letters
    numbers=1,  # need min. 2 digits
    strength=0.50 # need a password that scores at least 0.5 with its entropy bits
)

# Change this to your secret key (can be anything, it's for extra protection)
app.secret_key = 'WHYDOYOUNOTWORKHUH'


# Enter your database connection details below
app.config['MYSQL_HOST'] = "localhost"
app.config['MYSQL_USER'] = "root"
app.config['MYSQL_PASSWORD'] = "Lolzlife101"
app.config['MYSQL_DB'] = "pythonlogin"
app.config['RECAPTCHA_SITE_KEY'] = '6LerU_ogAAAAAM3UWoEhSj1ups9Buupha2vEJzD3'
app.config['RECAPTCHA_SECRET_KEY'] = '6LerU_ogAAAAAPfspsQwzHXxcDYlBIhckQJw_af_'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_DEFAULT_SERVER']='donotusetester7@gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'gayhoe69wannabe@gmail.com'
app.config['MAIL_PASSWORD'] = 'chbbejmmmlppqnxt'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
mail = Mail(app)
s = "Pleaseworkpleaseplease"

recaptcha = ReCaptcha(app)
Bootstrap(app)


# Intialize MySQL
mysql = MySQL(app)
# http://localhost:5000/MyWebApp/ - this will be the login page, we need to use both GET and POST
#requests
@app.route('/', methods=['GET', 'POST'])
def login():
    # Output message if something goes wrong...
    msg = ''
    # Check if "username" and "password" POST requests exist (user submitted form)
    try:
        print(session['attempt'])
    except:
        session['attempt'] = 2
    if request.method == 'POST' and 'username' in request.form and 'passworddd' in request.form:
    # Create variables for easy access
        username = request.form['username']
        password = request.form['passworddd']        
        if request.method == 'POST': # Check to see if flask.request.method is POST
            if recaptcha.verify(): # Use verify() method to see if ReCaptcha is filled out
        # Check if account exists using MySQL
                cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
                mysql.connection.commit()
            # Fetch one record and return result
                account = cursor.fetchone()
                
                cursor.execute('select password from accounts where username = %s', (username,))
                mysql.connection.commit()
                sqlPassword = cursor.fetchone()['password']
                passwd = {"password" : password}
                ptsd = jwt.encode(passwd, s , algorithm="HS256")

                #To check whether login is successful or not
                sql_cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                sql_cursor.execute('SELECT username, password FROM accounts WHERE username = %s', (username, ))
                sql_account = sql_cursor.fetchone()
                if ptsd == sql_account['password']:
                #if bcrypt.checkpw(passwd, (sqlPassword.encode('utf-8'))):
                # Create session data, we can access this data in other route 
                    session['loggedin'] = True
                    session['id'] = account['id']
                    session['username'] = account['username'] 

                    logger.info("Log in successful " + sql_account['username'])
                    #After verifying
                    session.permanent = True
                    # Redirect to home page
                
                else:
                    super_logger.error("Log in unsuccessful " + sql_account['username'])
                    attempt= session.get('attempt')
                    attempt -= 1
                    session['attempt']=attempt
                    msg = 'Incorrect username/password!'
                    if attempt==1:
                        flash("This will be your last attempt or you will be blocked for 7 minutes.")
                        return render_template("index.html")
                    else:
                        starttime = time.time()
                        if request.method == 'POST' and 'username' in request.form and 'passworddd' in request.form:
                            stoptime = time.time()
                            if (stoptime - starttime) < 30:
                                flash("You are still being blocked out.")
                                return render_template("index.html")
                            else:
                                flash('', 'error')
                                return render_template("index.html")
            
                return redirect(url_for("login_2fa", msg=msg))
            else:
                flash('Please fill out the ReCaptcha!')
                return render_template('index.html', msg=msg)  
    else:
        # Account doesn’t exist or username/password incorrect
        #msg = 'Incorrect username/password!'
        return render_template('index.html', msg=msg)    
# Show the login form with message (if any)


#logout
@app.route('/logout')
def logout():
    
# Remove session data, this will log the user out
    session.permanent = True
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)

    #flash('You have succesfully logged out!')

# Redirect to login page
    
    return redirect(url_for('login'))


#register
@app.route('/register', methods=['GET', 'POST'])
def register():
# Output message if something goes wrong...
    msg = ''
# Check if "username", "password" and "email" POST requests exist (user submitted form)
    if request.method == 'POST' and 'username' in request.form and 'passwordd' in request.form and'emailb' in request.form and 'phoneno' in request.form:
# Create variables for easy access
        username = request.form['username']
        password = request.form['passwordd']
        email = request.form['emailb']
        phoneno = request.form['phoneno']
        stats = PasswordStats(password)
# Optional challenge : Check for duplicate acct and perform form validation
# Account doesnt exists and the form data is valid, now insert new account into accounts table
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        foundacc = cursor.execute('SELECT * FROM accounts WHERE email  = %s', (email, ))       
        if foundacc == 0:
            checkpolicy = policy.test(password)
            if stats.strength() < 0.50:
                print(stats.strength())
                msg = "Password not strong enough. Avoid consecutive characters and easily guessed words."
            elif stats.strength() > 0.50:
                # s=password
                # passwd = s.encode('utf-8')
                # salt = bcrypt.gensalt()
                # hashed = bcrypt.hashpw(passwd, salt)
                # passwords = hashed
                createpass = {"password": password}
                passwords = jwt.encode(createpass, s , algorithm="HS256")
                cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                cursor.execute('INSERT INTO accounts VALUES (NULL, %s, %s, %s, %s)', (username, passwords, email, phoneno, ))
                mysql.connection.commit()
                msg = 'You have successfully registered!'
        else:
            flash("Email is already registered !", "error")

    elif request.method == 'POST':
# Form is empty... (no POST data)
        msg = 'Please fill out the form!'
# Show registration form with message (if any)
    return render_template('register.html', msg=msg)

#home
# http://localhost:5000/MyWebApp/home - this will be the home page, onlyaccessible for loggedin users
@app.route('/MyWebApp/home')
def home():
    # Check if user is loggedin
    if 'loggedin' in session:
        # User is loggedin show them the home page
        if 'loggedin' not in session:
            make_Session_Permanent() == False
            return redirect(url_for('login'))
        return render_template('home.html', username=session['username'])
        
    # User is not loggedin redirect to login page
    
    return redirect(url_for('login'))

#profile
# http://localhost:5000/MyWebApp/profile - this will be the profile page, only accessible for loggedin users
@app.route('/MyWebApp/profile')
def profile():
# Check if user is loggedin
    if 'loggedin' in session:
    # We need all the account info for the user so we can display it on the profile page
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE id = %s', (session['id'],))
        account = cursor.fetchone()
        # Show the profile page with account info
        if 'loggedin' not in session:
            make_Session_Permanent() == False
            return redirect(url_for('login'))
        return render_template('profile.html', account=account)
        # User is not loggedin redirect to login page
    return redirect(url_for('login'))

#Pranawi's Work
#2FA Page
@app.route("/login/2fa/", methods=['GET', 'POST'])
def login_2fa():
    # generating random secret key for authentication
    secret = pyotp.random_base32()
    html = """
    <html>
        <div>
          <h5>Instructions!</h5>
          <ul>
            <li>Select time-based authentication.</li>
            <li>Submit the generated key in the form.</li>
          </ul>
        </div>
        <div>
          <label for="secret">Secret Token : </label>
          <b id="secret"> {0} </b>
        </div>
         
    """.format(secret)
    if 'loggedin' in session:
        user=session['username']
        print(user)

    mydb = connection.connect(host="localhost", database = 'pythonlogin',user="root", passwd="Lolzlife101",use_pure=True)
    query = "Select * from accounts;"
    result_dataFrame = pd.read_sql(query,mydb)
    mydb.close() #close the connection
    result_dataFrame = result_dataFrame[result_dataFrame['username'] == str(user)]

    email=list(result_dataFrame.email.values)[0]
    print(email)
    mail_content = html
    sender_address = 'tinay3871@gmail.com'
    sender_pass = 'amkgcotykxfjjigy'
    receiver_address = email
    message = MIMEMultipart()
    message['From'] = sender_address
    message['To'] = receiver_address
    message['Subject'] = 'A test mail sent by Python. It has an attachment.'   #The subject line
    message.attach(MIMEText(mail_content, 'html'))
    sessions = smtplib.SMTP('smtp.gmail.com', 587) #use gmail with port
    sessions.starttls()
    sessions.login(sender_address, sender_pass)
    text = message.as_string()
    sessions.sendmail(sender_address, receiver_address, text)
    sessions.quit()


    return render_template("login_2fa.html", secret=secret)


#@app.route('/blogs')
#def blog():
#    app.logger.info('Info level log')
#    app.logger.warning('Warning level log')
#    return f"Welcome to the blog"
@app.route('/forget_ID', methods =['GET', 'POST'])
def forgetID():
    if request.method == 'POST':
        if recaptcha.verify():
            IDretriever = request.form['IDEmail']
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            catchcheck = cursor.execute('SELECT * FROM accounts WHERE email = % s' , (IDretriever, ))
            if catchcheck != 0:
                flash(cursor.fetchone()['username'], "error")
            else:
                flash("Email not registered !", "error")
        else:
            flash("Please do reCaptcha")
        
        return render_template("forgetID.html")

    return render_template("forgetID.html")
    
    

@app.route("/forget_password", methods =['GET', 'POST'])
def forget_password():
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    global phoneNum
    try:
        if recaptcha.verify():
            getemail = jwt.decode(tokenenc, s, algorithms=["HS256"])
            cursor.execute('SELECT * FROM accounts WHERE email = % s' , (getemail['email'], ))
            if request.method == 'POST' and 'password' in request.form and 'confirm_pass' in request.form:
                password = request.form['password']   
                confirm_pass = request.form['confirm_pass'] 
                stats = PasswordStats(password)
                if not password or not confirm_pass:
                    flash('Please fill out the form !', "error")
                elif password != confirm_pass:
                    flash('Confirm password is not equal!', "error")
                else:
                    # Another connection to MySQL database
                    if stats.strength() < 0.50:
                        print(stats.strength())
                        flash("Password not strong enough. \n Avoid consecutive characters and easily guessed words.", "error")
                    elif stats.strength() > 0.50:
                        hashpass = {"password" : password}
                        encodedpass = jwt.encode(hashpass, s , algorithm="HS256")
                        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                        cursor.execute('UPDATE accounts SET password =% s WHERE email =% s', (encodedpass, (getemail['email']), ))
                        mysql.connection.commit()
                        return render_template("index.html")

            elif request.method == 'POST':
                flash('Please fill out the form !', category='error')   
                return render_template("forget_password.html")

    except:
        if recaptcha.verify():
            print("Enter")
            cursor.execute('SELECT * FROM accounts WHERE phoneno = % s' , (phoneNum, ))
            phoneno = cursor.fetchone()
            if request.method == 'POST' and 'password' in request.form and 'confirm_pass' in request.form :
                password = request.form['password']   
                confirm_pass = request.form['confirm_pass'] 
                phoneno = phoneNum
                stats = PasswordStats(password)
                if not password or not confirm_pass:
                    flash('Please fill out the form !', "error")
                elif password != confirm_pass:
                    flash('Confirm password is not equal!', "error")
                else:
                    # Another connection to MySQL database
                    if stats.strength() < 0.50:
                        flash("Password not strong enough. \n Avoid consecutive characters and easily guessed words.", "error")
                    elif stats.strength() > 0.50:
                        hashpass = {"password" : password}
                        encodedpass = jwt.encode(hashpass, s , algorithm="HS256")
                        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                        cursor.execute('UPDATE accounts SET password =% s WHERE phoneno =% s', (encodedpass, (phoneno), ))
                        mysql.connection.commit()
                        return render_template("index.html")

            elif request.method == 'POST':
                print(request.form)
                flash('Please fill out the form !', category='error')
                    
            return render_template("forget_password.html")

otp = ""
phoneNum = ""

@app.route("/phone_number", methods =['GET', 'POST']) #Check for user later 
def phone_num():
    mesage = ''
    if request.method == "POST":
        num = request.form ['number']
        global phoneNum
        phoneNum = num
        global otp
        try:
            otp = getOTPApi(num)
            if num:
                return redirect(url_for("getOTP", mesage = mesage))                
        except:
            flash(u"Number is not registered.", "error")
            return render_template("phone_number.html", mesage = mesage)
    else:
        return render_template("phone_number.html")

@app.route("/getOTP", methods =['GET', 'POST']) 
def getOTP():
    if request.method == "GET":
        return render_template("getOTP.html")
    else:
        formAns = request.form ['OTP']
        global otp
        try:
            if otp == formAns:
                return render_template("forget_password.html")
            else:
                flash(u"Please enter the correct otp", "error")
                return render_template("getOTP.html")
        except:
            #flash(u"Please enter the correct otp", "error")
            #return render_template("getOTP.html")
            return render_template("404.html")
        
def generateOTP():
    return random.randint(100000,999999)

def getOTPApi(number):
    account_sid = "AC6d699aeaa01fc41b674dac09ab7b9f9c"
    auth_token = "8bff873d2b1c45c44f6243f721f6fc40"
    client = Client(account_sid, auth_token)
    otp = generateOTP()
    body = 'Your OTP is' + str(otp)
    session['response'] = str(otp)
    mesage = client.messages.create(from_='+13253356303', body = body, to=number)

    if mesage.sid:
        return str(otp)
    else:
        False

@app.route("/error", methods =['GET', 'POST']) #Check for user later 
def error():
    return render_template("404.html")

tokenenc = ''

@app.route('/email', methods =['GET', 'POST'])
def email():
    if request.method == 'POST' :
        emailadd = request.form['emaila']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        if cursor.execute('Select * from accounts WHERE email =%s', (emailadd, )) == 0:
            flash('Email not register !')
            return render_template('email.html')
        else:
            storeemail = {"email":emailadd}
            global tokenenc
            tokenenc = jwt.encode(storeemail, s, algorithm="HS256")
            storeemail["email"] = tokenenc
            msg = Message('Reset Password', sender = 'donotusetester7@gmail.com', recipients = [emailadd])
            link = url_for('token', token=token, _external=True)
            msg.body = "Please reset your password with the link given to you below.\n Your token will expire in 5 minutes. \n Your token is : {} \n {}".format(tokenenc, link)
            mail.send(msg)
            global start
            start = time.time()
            flash('Email has been sent !', 'error')
            return render_template('email.html')


    else:
        return render_template('email.html')

@app.route('/token', methods =['GET', 'POST'])
def token():
    if request.method == 'POST':
        #verification here
        if request.form["tokentaken"] == tokenenc:
            stop = time.time()
            if stop-start > 300:
                flash("Token has expired !")
                return render_template('404.html')
            else:
                return render_template('forget_password.html')
        else:
            flash('Incorrect token')
    try: #useless
        emailadd = jwt.decode(tokenenc, s, algorithms=["HS256"], max_age=30)
    except:
        return render_template('404.html')
    return render_template('token.html')

@app.route("/addProduct", methods=["GET", "POST"])
def addProduct():
    add_product_form = AddProductForm(request.form)
    try:
        product_dict = {}
        product_database = shelve.open('product.db', 'c')

        if 'products' in product_database:
            product_dict = product_database['products']
        else:
            product_database['products'] = product_dict

    except Exception as e:
        flash(f"Something unexpected occurred {e}", category='error')
    if request.method == "POST":
        #log_database = shelve.open('log.db', 'c')
        #log_dict = {}
        #if 'log' in log_database:
            #log_dict = log_database['log']
        #else:
            #log_database['log'] = log_dict



        product = Product(name=add_product_form.product_name.data, description=add_product_form.product_description.data,
                          price=add_product_form.product_price.data, quantity=add_product_form.product_quantity.data)
        image = request.files['image']
        if not image:
            flash("No picture is uploaded")
        else:
            string = base64.b64encode(image.read())
            product.set_image(string)
        #log = ActionLog(description = product, title="Staff has added a product", user=current_user.username, action="Add")
        #log_dict[log.get_id()] = log
        #log_database['log'] = log_dict
        #log_database.close()
        product_dict[product.get_id()] = product
        product_database['products'] = product_dict

        product_dict[product.get_id()] = product
        product_database['products'] = product_dict

        return redirect(url_for("inventory"))
    product_database.close()

    return render_template("addProduct.html", add_product_form=add_product_form, product_dict=product_dict)


@app.route("/inventory")
def inventory():
    try:
        product_dict = {}
        product_database = shelve.open('product.db', 'c')

        if 'products' in product_database:
            product_dict = product_database['products']
        else:
            product_database['products'] = product_dict

    except Exception as e:
        pass
    return render_template('inventory.html', product_dict=product_dict)


@app.route("/deleteProduct", methods=["GET", "POST"])
def deleteProduct():
    if request.method == "POST":
        try:
            product_dict = {}
            product_database = shelve.open('product.db', 'c')

            if 'products' in product_database:
                product_dict = product_database['products']
            else:
                product_database['products'] = product_dict

        except Exception as e:
            pass
        else:
            del product_dict[request.form.get('uuid')]
            product_database['products'] = product_dict
            product_database.close()
    return redirect(url_for("inventory"))

@app.route("/updateProduct/<string:id>", methods=["GET", "POST"])
def updateProduct(id):
    update_product_form = AddProductForm(request.form)
    if request.method == 'POST' and update_product_form.validate():
        product_dict = {}
        product_database = shelve.open('product.db', 'c')
        product_dict = product_database['products']

        product = product_dict.get(id)
        product.set_name(update_product_form.product_name.data)
        product.set_price(update_product_form.product_price.data)
        product.set_quantity(update_product_form.product_quantity.data)
        product.set_description(update_product_form.product_description.data)

        product_database['products'] = product_dict
        product_database.close()

        return redirect(url_for('inventory'))
    else:
        product_dict = {}
        product_database = shelve.open('product.db', 'c')
        if 'products' in product_database:
            product_dict = product_database['products']
        else:
            product_database['products'] = product_dict
        product_database.close()

        product = product_dict[id]
        update_product_form.product_name.data = product.get_name()
        update_product_form.product_price.data = product.get_price()
        update_product_form.product_quantity.data = product.get_quantity()
        update_product_form.product_description.data = product.get_description()

    return render_template('updateProduct.html', update_product_form=update_product_form, product_dict=product_dict, id=id)
@app.route("/notes", methods=["GET", "POST"])
def notes():
    try:
        user_notes = {}
        add_notes_form = AddNotes(request.form)
        notes_database = shelve.open('notes.db', 'c')
        if 'notes' not in notes_database:
            notes_database['notes'] = user_notes
        else:
            user_notes = notes_database['notes']

    except:
        pass
    else:

        if request.method == "POST" and add_notes_form.validate():
            new_note = Notes(title=add_notes_form.title.data, description=add_notes_form.description.data,
                             time_added=datetime.now().strftime("%d/%m/%y"), time_updated=datetime.now().strftime("%d/%m/%y"))
            user_notes[new_note.get_id()] = new_note
            print(user_notes)
            notes_database['notes'] = user_notes
            notes_database.close()
            return redirect(url_for("notes"))
    notes_database.close()

    return render_template("notes.html", add_notes_form=add_notes_form, user_notes=user_notes)


@app.route("/deleteNotes", methods=["GET", "POST"])
def deleteNotes():
    if request.method == "POST":
        try:
             notes_database = shelve.open('notes.db', 'w')
             user_notes = {}
             if 'notes' not in notes_database:
                notes_database['notes'] = user_notes
             else:
                user_notes = notes_database['notes']


        except KeyError:
            pass
        else:
            print(user_notes)

            print(request.form.get('uuid'))

            del user_notes[str(request.form.get('uuid'))]



            notes_database['notes'] = user_notes

            notes_database.close()
    return redirect(url_for("notes"))


@app.route("/updateNotes", methods=["GET", "POST"])
def updateNotes():
    if request.method == "POST":

        try:
            notes_database = shelve.open('notes.db', 'w')
            user_notes = {}
            if 'notes' not in notes_database:
                notes_database['notes'] = user_notes
            else:
                user_notes = notes_database['notes']

        except KeyError:
            pass
        current_note = user_notes[request.form.get('uuid')]

        current_note.set_title(request.form.get('title'))
        current_note.set_description(request.form.get('description'))

        current_note.set_time_updated(datetime.now().strftime("%d/%m/%y"))

        notes_database['notes'] = user_notes
        notes_database.close()

    return redirect(url_for("notes"))
@app.route("/suppliers", methods=["GET", "POST"])
def suppliers():
    add_suppliers = AddSuppliersForm(request.form)
    try:

        supplier_database = shelve.open('supplier.db', 'c')
        supplier_dict = {}
        if 'supplier' in supplier_database:
            supplier_dict = supplier_database['supplier']
        else:
            supplier_database['supplier'] = supplier_dict

        supplier_database.close()
    except Exception as e:
        pass
    supplier_dict = dict(reversed(supplier_dict.items()))
    if request.method == "POST":


        supplier = supplier_dict[request.form.get('uuid')]
        supplier.set_status("unedited")
        add_suppliers.suppliers_name.data = supplier.get_name()
        add_suppliers.suppliers_description.data = supplier.get_description()
        add_suppliers.products.data = ','.join(
            supplier.get_product_in_charge())

    return render_template("suppliers.html", supplier_dict=supplier_dict, add_suppliers=add_suppliers)
@app.route("/addSupplier", methods=["GET", "POST"])
def addSupplier():
    try:
        supplier_dict = {}
        supplier_database = shelve.open("supplier.db", 'c')

        if 'supplier' in supplier_database:
            supplier_dict = supplier_database['supplier']
        else:
            supplier_database['supplier'] = supplier_dict

    except Exception as e:
        pass
    if request.method == "GET":
        supplier = Supplier()
        supplier_dict[supplier.get_id()] = supplier
        supplier_database['supplier'] = supplier_dict
    elif request.method == 'POST':


        add_suppliers = AddSuppliersForm(request.form)
        supplier = supplier_dict[request.form.get('uuid')]
        supplier.set_status("edited")
        supplier.set_name(add_suppliers.suppliers_name.data)
        supplier.set_product_in_charge(
            str(add_suppliers.products.data).replace(" ", "").split(","))
        supplier.set_description(add_suppliers.suppliers_description.data)

        supplier_database['supplier'] = supplier_dict
        supplier_database.close()
    return redirect(url_for('suppliers'))


@app.route("/removeSupplier", methods=["GET", "POST"])
def removeSupplier():
    try:
        supplier_dict = {}

        supplier_database = shelve.open("supplier.db", 'c')
        if 'supplier' in supplier_database:
            supplier_dict = supplier_database['supplier']
        else:
            supplier_database['supplier'] = supplier_dict
    except Exception as e:
        pass
    if request.method == 'POST':
        del supplier_dict[request.form.get('uuid')]
    supplier_database['supplier'] = supplier_dict
    supplier_database.close()
    return redirect(url_for('suppliers'))
if __name__== '__main__':
    #first file logger
    logger = setup_logger('first_logger', 'record.log')


    #second file logger
    super_logger = setup_logger('second_logger', 'error.log')
    
    app.run(debug=True)


from flask import Flask, render_template, request,session,logging,url_for,redirect,flash,jsonify,make_response
import jwt
from datetime import datetime, timedelta
from functools import wraps
from flask_sqlalchemy import sqlalchemy
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from passlib.hash import sha256_crypt

engine = create_engine("mysql+pymysql://root:teddyathome@localhost/register")
db = scoped_session(sessionmaker(bind=engine))

app = Flask(__name__)
app.config['SECRET_KEY'] = 'fcc5516cd5c04f73beececbae26c895a'

@app.route("/home")
def home():
    if not session.get('log'):
        flash('Session has been logged out', 'danger')
        return redirect(url_for('login'))
    else:
        return render_template('home.html')

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")
        secure_password =sha256_crypt.encrypt(str(password))

        if password == confirm_password:
            db.execute("INSERT INTO users(username, email, password) VALUES(:username,:email,:password)",
                        {"username":username,"email":email,"password":secure_password})
            db.commit()
            flash("You are registered successfully", "success")
            return redirect(url_for('login'))
        else:
            flash("password does not match", "danger")
            return render_template("register.html")

    return render_template("register.html")

def token_required(func):
    @wraps(func)
    def decorated(*args, **kwargs):
        token = request.args.get('token')
        if not token:
            return jsonify({'Alert!': 'Token is missing!'})
        try:
            payload = jwt.decode(token, app.config['SECRET_KEY'])
        except:
            return jsonify({'Alert!': 'Invalid Token!'})
    return decorated

        

@app.route("/", methods=["GET","POST"])
def login():
    if request.method=="POST":
        username = request.form.get("username")
        password = request.form.get("password")

        usernamedata = db.execute("SELECT username FROM users WHERE username=:username",{"username":username}).fetchone()
        passworddata = db.execute("SELECT password FROM users WHERE username=:username",{"username":username}).fetchone()

        if usernamedata is None:
            flash("User not found", "danger")
            return render_template("login.html")
        else:
            for password_data in passworddata:
                if sha256_crypt.verify(password,password_data):
                    session["log"] = True
                    token = jwt.encode({
                        'username':request.form['username'],
                        'expiration': str(datetime.utcnow() + timedelta(seconds=300))
                    },app.config['SECRET_KEY'])
                    flash("You are logged in successfully", "success")
                    print(jsonify({'token':token.decode('utf-8')}))
                    return redirect(url_for('home'))
                else:
                    flash("Incorrect passwrod","danger")
                    return render_template("login.html")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session["log"] = False
    return redirect(url_for('login'))

if __name__ == "__main__":
    app.secret_key="teddyathome"
    app.run(debug=True)

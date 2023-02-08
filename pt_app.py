from flask import Flask, render_template, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError, Email

# Creating the Flask app
app = Flask(__name__)

# Configuring the SQLAlchemy database with the URI and setting the secret key
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///db.sqlite"
app.config["SQLALCHEMY_TRACK_MODIFICATION"] = False
app.config["SECRET_KEY"] = "811981"

# Initializing the extension
db = SQLAlchemy(app)

# Creating the databse tables
with app.app_context():
    db.create_all()

# Creating the clinet model
class Client(db.Model, UserMixin):
    client_id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(30), nullable = False)
    surname = db.Column(db.String(30), nullable = False)
    address = db.Column(db.String(50), nullable = False)
    email = db.Column(db.String(30), nullable = False)
    password = db.Column(db.string(80), nullable = False)

# Creating the trainer model
class Trainer(db.Model, UserMixin):
    trainer_id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(30), nullable=False)
    surname = db.Column(db.String(30), nullable=False)
    address = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(30), nullable=False)
    password = db.Column(db.String(80), nullable =False)
    specialization = db.Column(db.String(50), nullable=False)

# Creating the sessionsmodel
class Sessions(db.Model, UserMixin):
    session_id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.Integer, db.ForeignKey("client.client_id"), nullable=False)
    date = db.Column(db.Date, nullable=False)
    time = db.Column(db.Time, nullable=False)
    location = db.Column(db.String(50), nullable=False)

class ClientRegisterForm(FlaskForm):
    first_name = StringField("First Name", validators=[InputRequired(), Length(max=30)])
    surname = StringField("Surname", validators=[InputRequired(), Length(max=30)])
    address = StringField("Address", validators=[InputRequired(), Length(max=50)])
    email = StringField("Email", validators=[InputRequired(), Email(), Length(max=30)])
    password = StringField("Password", validators=[InputRequired(), Length(min=4, max=20)])



@app.route("/")
def home():
    return render_template("home.html")

@app.route("/login")
def login():
    return render_template("login.html")

@app.route("/client_signup")
def client_signup():
    return render_template("client_signup.html")

@app.route("/trainer_signup")
def trainer_signup():
    return render_template("trainer_signup.html")

if __name__ == "__main__":
    app.run(debug=True)

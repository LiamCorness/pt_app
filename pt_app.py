from flask import Flask, render_template, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError, Email
import email_validator

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

# Function to check if entered email is already registered
def validate_email(form, field):
    if Client.query.filter_by(email=field.data).first() or Trainer.query.filter_by(email=field.data).first():
        raise ValidationError("Email already registered")

# Creating the client model
class Client(db.Model, UserMixin):
    client_id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(30), nullable = False)
    surname = db.Column(db.String(30), nullable = False)
    address = db.Column(db.String(50), nullable = False)
    email = db.Column(db.String(30), nullable = False, unique=True)
    password = db.Column(db.String(80), nullable = False)

# Creating the trainer model
class Trainer(db.Model, UserMixin):
    trainer_id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(30), nullable=False)
    surname = db.Column(db.String(30), nullable=False)
    address = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(30), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable =False)
    specialization = db.Column(db.String(50), nullable=True)

# Creating the sessions model
class Sessions(db.Model, UserMixin):
    session_id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.Integer, db.ForeignKey("client.client_id"), nullable=False)
    date = db.Column(db.Date, nullable=False)
    time = db.Column(db.Time, nullable=False)
    location = db.Column(db.String(50), nullable=False)

# Create client register form class
class ClientRegisterForm(FlaskForm):
    first_name = StringField("First Name", validators=[InputRequired(), Length(max=30)])
    surname = StringField("Surname", validators=[InputRequired(), Length(max=30)])
    address = StringField("Address", validators=[InputRequired(), Length(max=50)])
    email = StringField("Email", validators=[InputRequired(), Email(), Length(max=30)])
    password = StringField("Password", validators=[InputRequired(), Length(min=4, max=20)])

    # Submit button
    submit = SubmitField("Register")

# Create trainer reguster form class
class TrainerRegisterForm(FlaskForm):
    first_name = StringField("First Name", validators=[InputRequired(), Length(max=30)])
    surname = StringField("Surname", validators=[InputRequired(), Length(max=30)])
    address = StringField("Address", validators=[InputRequired(), Length(max=50)])
    email = StringField("Email", validators=[InputRequired(), Email(), Length(max=30), validate_email])
    password = StringField("Password", validators=[InputRequired(), Length(min=4, max=20)])
    specialization = StringField("Specialization", validators=[Length(max=50)])

    # Submit button
    submit = SubmitField("Register")


class Login(FlaskForm):
    email = StringField("Enter your Email : ", validators=[InputRequired(), Email(), Length(max=30)])
    password = StringField("Password : ", validators=[InputRequired(), Length(min=4, max=20)])

    submit = SubmitField("Log in")



@app.route("/")
def home():
    return render_template("home.html")

@app.route("/login",methods=["GET","POST"] )
def login():
    form = Login()
    return render_template("login.html", form=form )

@app.route("/client_signup", methods=["GET","POST"])
def client_signup():
    form = ClientRegisterForm()
    return render_template("client_signup.html", form=form)

@app.route("/trainer_signup", methods=["GET", "POST"])
def trainer_signup():
    form = TrainerRegisterForm()
    return render_template("trainer_signup.html", form=form)

if __name__ == "__main__":
    app.run(debug=True)

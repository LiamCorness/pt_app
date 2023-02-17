from flask import Flask, render_template, url_for, redirect, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError, Email
from flask_bcrypt import Bcrypt, check_password_hash
from sqlalchemy import create_engine, Column, Integer, String, MetaData, exc
from sqlalchemy.exc import IntegrityError


# Creating the Flask app
app = Flask(__name__)

# Configuring the SQLAlchemy database with the URI and setting the secret key
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///db.sqlite"
app.config["SQLALCHEMY_TRACK_MODIFICATION"] = False
app.config["SECRET_KEY"] = "811981"

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


# Initializing the extension
db = SQLAlchemy(app)

bcrypt = Bcrypt(app)

# Function to check if entered email is already registered
def validate_email(form, field):
    if Client.query.filter_by(email=field.data).first() or Trainer.query.filter_by(email=field.data).first():
        raise ValidationError("Email already registered")

# Creating the client model
class Client(db.Model, UserMixin):
    # I will change code so that the ID is automatically created for each user
    client_id = db.Column(db.Integer(), primary_key=True , autoincrement=True)
    first_name = db.Column(db.String(30), nullable = False)
    surname = db.Column(db.String(30), nullable = False)
    address = db.Column(db.String(50), nullable = False)
    email = db.Column(db.String(30), nullable = False, unique=True)
    password = db.Column(db.String(80), nullable = False)

    def __init__(self, first_name, surname, address, email, password):
        self.first_name = first_name
        self.surname = surname
        self.address = address
        self.email = email
        self.password = password
    
    def get_id(self):
        return (self.client_id)

        
# Creating the trainer model
class Trainer(db.Model, UserMixin):
    trainer_id = db.Column(db.Integer(), primary_key=True, autoincrement=True)
    first_name = db.Column(db.String(30), nullable=False)
    surname = db.Column(db.String(30), nullable=False)
    address = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(30), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable =False)
    specialization = db.Column(db.String(50), nullable=True)

    def __init__(self, first_name, surname, address, email, password, specialization):
        self.first_name = first_name
        self.surname = surname
        self.address = address
        self.email = email
        self.password = password
        self.specialization = specialization

    def get_id(self):
        return (self.trainer_id)


# Creating the sessions model
class Sessions(db.Model, UserMixin):
    session_id = db.Column(db.String, primary_key=True)
    client_id = db.Column(db.String, db.ForeignKey("client.id"), nullable=False)
    date = db.Column(db.Date, nullable=False)
    time = db.Column(db.Time, nullable=False)
    location = db.Column(db.String(50), nullable=False)

    def get_id(self):
        return str(self.client_id)

with app.app_context():
    db.create_all()

# Create client register form class
class ClientRegisterForm(FlaskForm):
    def validate_password(form,field):
        password=field.data
        if len(password) < 8:
            raise ValidationError("Password must be at least 8 character long.")
        if not any(char.isdigit() for char in password):
            raise ValidationError("Password must contain at least one number")
        if not any(char in '!@#$%^&*()_-+=[{]}\|;:"<,>.?/' for char in password):
            raise ValidationError("Password must contain at least one special character")
        
    def validate_confirm_password(self, confirm_password):
        if self.password.data != self.confirm_password.data:
            raise ValidationError('Passwords must match.')

    first_name = StringField("First Name", validators=[InputRequired(), Length(max=30)])
    surname = StringField("Surname", validators=[InputRequired(), Length(max=30)])
    address = StringField("Address", validators=[InputRequired(), Length(max=50)])
    email = StringField("Email", validators=[InputRequired(), Email(), Length(max=30)])
    password = PasswordField("Password", validators=[InputRequired(), Length(min=4, max=20), validate_password, validate_confirm_password])
    confirm_password = PasswordField("Confirm Password", validators=[InputRequired(), Length(min=4, max=20)])

    # Submit button
    submit = SubmitField("Register")

# Create trainer register form class
class TrainerRegisterForm(FlaskForm):
    def validate_password(form,field):
        password=field.data
        if len(password) < 8:
            raise ValidationError("Password must be at least 8 character long.")
        if not any(char.isdigit() for char in password):
            raise ValidationError("Password must contain at least one number")
        if not any(char in '!@#$%^&*()_-+=[{]}\|;:"<,>.?/' for char in password):
            raise ValidationError("Password must contain at least one special character")
        
    def validate_confirm_password(self, confirm_password):
        if self.password.data != self.confirm_password.data:
            raise ValidationError('Passwords must match.')


    first_name = StringField("First Name", validators=[InputRequired(), Length(max=30)])
    surname = StringField("Surname", validators=[InputRequired(), Length(max=30)])
    address = StringField("Address", validators=[InputRequired(), Length(max=50)])
    email = StringField("Email", validators=[InputRequired(), Email(), Length(max=30), validate_email])
    password = PasswordField("Password", validators=[InputRequired(), Length(min=4, max=20), validate_password, validate_confirm_password])
    confirm_password = PasswordField("Confirm Password", validators=[InputRequired(), Length(min=4, max=20)])
    specialization = StringField("Specialization", validators=[Length(max=50)])

    # Submit button
    submit = SubmitField("Register")

class Login(FlaskForm):
    email = StringField("Enter your Email : ", validators=[InputRequired(), Email(), Length(max=30)])
    password = PasswordField("Password : ", validators=[InputRequired(), Length(min=4, max=20)])

    submit = SubmitField("Log in")

@app.route("/")
def home():
    return render_template("home.html")

@app.route("/login",methods=["GET","POST"] )
def login():

    form = Login()
    user_info = {}
    # If the form is submitted and valid
    if form.validate_on_submit():
        # Get the entered email from the form
        email = form.email.data
        # Get the user that matches the entered email
        client = Client.query.filter_by(email=email).first()
        trainer = Trainer.query.filter_by(email=email).first()

        # If a user is found
        if client or trainer:
        # Get the password from the form
            password = form.password.data
        
        # Check if the entered password matches the password in the database
        if (client and bcrypt.check_password_hash(client.password, password)) or (trainer and bcrypt.check_password_hash(trainer.password, password)):
            # Log the user in and redirect to appropiate landing page based on user type
            if client:
                login_user(client)
                session["user_email"] = client.email
                session["user_name"] = (f"{client.first_name} {client.surname}")
                return redirect(url_for("client_dashboard"))
            elif trainer:
                login_user(trainer)
            return redirect(url_for("trainer_dashboard"))

        # If no user is found or the password doesn't match
        form.email.errors.append("Invalid Email/Password")

        if client:

            user_info = {
            "name": f"{client.firstname} {client.surname}",
            "email": client.email
            }
    
        if trainer:
            user_info = {
                "name": f"{trainer.firstname} {trainer.surname}",
                "email": trainer.email
                }


    return render_template("login.html", form=form)

@app.route("/client_signup", methods=["GET","POST"])
def client_signup():
    form = ClientRegisterForm()
    # Whenever the form is submitted a hashed version of the password is generated
    # Then create a new user and add them to database
    if form.validate_on_submit():
        try:
            hashed_password = bcrypt.generate_password_hash(form.password.data)
            client = Client(first_name=form.first_name.data, surname=form.surname.data, address=form.address.data, email=form.email.data, password=hashed_password)
            client_id = client.client_id
            db.session.add(client)
            db.session.commit()
            return redirect(url_for("login"))
        except IntegrityError as e:
            if "UNIQUE constraint failed" in str(e):
                flash("A user with the same id number or email already exists.")
            else:
                app.logger.error(e)
                flash("An error occurred while registering. Please try again later")
            db.session.rollback()
        except ValidationError as e:
            flash(str(e))
            db.session.rollback()


    return render_template("client_signup.html", form=form)

@app.route("/trainer_signup", methods=["GET", "POST"])
def trainer_signup():
    form = TrainerRegisterForm()
     # Whenever the form is submitted a hashed version of the password is generated
    # Then create a new user and add them to database
    if form.validate_on_submit():
        try:
            hashed_password = bcrypt.generate_password_hash(form.password.data)
            trainer = Trainer(first_name=form.first_name.data, surname=form.surname.data, address=form.address.data, email=form.email.data, password=hashed_password, specialization=form.specialization.data)
            trainer_id = trainer.trainer_id()
            db.session.add(trainer)
            db.session.commit()
            return redirect(url_for('login'))
        except IntegrityError as e:
            if "UNIQUE constraint failed" in str(e):
                flash("An error occurred while registering. Please try again later")
            db.session.rollback()
        except ValidationError as e:
            flash(str(e))
            db.session.rollback()
        

    return render_template("trainer_signup.html", form=form)

@app.route("/trainer_dashboard", methods=["GET", "POST"])
@login_required
def trainer_dashboard():
    return render_template("trainer_dashboard.html")

@app.route("/client_dashboard", methods=["GET", "POST"])
@login_required
def client_dashboard():
    return render_template("client_dashboard.html")

@app.route("/logout", methods=["GET", "POST"])
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

@app.route("/client_profile", methods=["GET", "POST"])
@login_required
def client_profile():
    user_info = {
        "name": f"{current_user.first_name} {current_user.surname}",
        "email": current_user.email
    }
    return render_template("client_profile.html", user_info=user_info)

@app.route("/trainer_list", methods=["GET", "POST"])
@login_required
def trainer_list():
    trainers = Trainer.query.all()

    return render_template("trainer_list.html", trainers=trainers)


@login_manager.user_loader
def load_user(user_id):

    user = Client.query.get(int(user_id))
    if user:
        return user
    return Trainer.query.get(int(user_id)) 

                            
if __name__ == "__main__":
    app.run(debug=True)

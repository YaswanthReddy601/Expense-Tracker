#importing the required packages
from flask import Flask, render_template, request, url_for, flash, session
from flask_login import login_user, LoginManager, UserMixin, current_user, login_required, logout_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from Tables import RegisterForm, Login, expenses
from werkzeug.utils import redirect

#creating flask application object and setting static flask url path in flask
app = Flask(__name__, static_url_path='/static')

#Tracks the modifications of the objects and occupies more memory. So to  save the memory and wornings we disabled it
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
#database name
app.config['SQLALCHEMY_DATABASE_URI']= "sqlite:///expense.db"
app.config["SECRET_KEY"]="ZXCVBNM."

#instantiating the DB
db = SQLAlchemy(app)

#Creating databases
class Authentication(db.Model, UserMixin):
    id= db.Column(db.Integer, primary_key=True)
    name= db.Column(db.String, nullable=False)
    email= db.Column(db.String, unique=True, nullable=False)
    password= db.Column(db.String, nullable=False)
    salary= db.Column(db.Integer)

with app.app_context():
    db.create_all()

class Data(db.Model, UserMixin):
    id= db.Column(db.Integer, primary_key=True)
    email= db.Column(db.String, nullable=False)
    purpose= db.Column(db.String, nullable=False)
    cost= db.Column(db.Integer, nullable=False)

with app.app_context():
    db.create_all()


@app.route('/')
def home():
    #Shows menu page, if user not logged in
    try:
        if current_user.email:
            return redirect(url_for("options"))
    #Shows home page, when user not logged in
    except:
        return render_template('home_page.html')


@app.route("/signup", methods=['POST', "GET"])
def signup():
    #checks if current user logged out our not
    try:
        if current_user.email:
            return redirect(url_for("options"))
    #if logged out the shows sign in page
    except:
        data= RegisterForm()
        if request.method == "POST":
            email_ = data.email.data
            user= Authentication.query.filter_by(email=email_).first()
            #if the email is already exist in database then the following flash message will be appeared else user will be reqistered successfully
            if user is not None:
                flash("Email already registered!")
                return redirect(url_for("signup"))
            else:
                #hashing the given password
                hashed_password= generate_password_hash(data.password.data, method="pbkdf2:sha256", salt_length=5)
                new_user= Authentication(
                    name= data.name.data,
                    email= data.email.data,
                    password= hashed_password,
                    salary= data.salary.data
                )
                db.session.add(new_user)
                db.session.commit()
                return redirect(url_for("home"))
        return render_template("signup.html")

@app.route("/login", methods=["POST", "GET"])
def login():
    #checks if current user logged out our not
    try:
        if current_user.email:
            print("a")
            return redirect(url_for("options"))
    except:
        login= Login()
        if request.method == "POST":
            mail= login.email.data
            user=Authentication.query.filter_by(email=mail).first()
            #checks if user is in DB or not
            if user:
                password= login.password.data
                #compares the the given password with password in DB
                if check_password_hash(user.password, password):
                    login_user(user)
                    return redirect(url_for('options'))
                else:
                    #shows flash messages if any of the given details is mismatched
                    flash("Wrong password.")
                    return render_template("login.html")
            else:
                flash("Email not registered.")
                return render_template("login.html")
        else:
            return render_template("login.html")

@app.route("/options")
@login_required
def options():
    #opens the menu(options.html page)
    return render_template('options.html')

#this contains the code that application and flask-login work together
loginmanager= LoginManager()
#initialize the application
loginmanager.init_app(app)

#It helps the flask-login, how to load the user Id
@loginmanager.user_loader
def load_user(user_id):
    return Authentication.query.get(int(user_id))

#Adds the expenses to the DB
@app.route("/exp", methods=["POST", "GET"])
@login_required
def expense():
    ex= expenses()
    if request.method == "POST":
        purpose_= ex.purpose.data
        cost_= ex.cost.data
        new_data= Data(
            email= current_user.email,
            purpose= purpose_,
            cost= cost_,
        )
        db.session.add(new_data)
        db.session.commit()
        return redirect(url_for('all_data'))
    return render_template("Expense.html")

#Shows the expenses from the DB using HTML page
@app.route("/data", methods=["POST", "GET"])
@login_required
def all_data():
    salary_= current_user.salary
    all_data = Data.query.filter_by(email=current_user.email).all()
    return render_template('data.html', expenses=all_data, salary=salary_)


@app.route("/update", methods=['POST', 'GET'])
@login_required
def modefy():
    if request.method == "POST":
        income= request.form.get("salary")
        name= request.form.get("name")
        #Gets the current user data from BD and updates it
        user = Authentication.query.get(current_user.id)
        user.salary= income
        user.name= name
        db.session.commit()
        return redirect(url_for('options'))
    else:
        return render_template('update.html', data= current_user)

@app.route("/del")
@login_required
def delete():
    #Gets the current user data from BD and deletes it
    user= Authentication.query.get(current_user.id)
    db.session.delete(user)
    db.session.commit()
    logout_user()
    return redirect(url_for('home'))


@app.route("/remove/<int:expense_id>")
@login_required
def delete_data(expense_id):
    #Gets the expense data based on the route parameter id and deletes it
    expense = Data.query.get(expense_id)
    db.session.delete(expense)
    db.session.commit()
    return redirect(url_for("all_data"))

@app.route("/mod/<int:expense_id>", methods=["POST", "GET"])
@login_required
def update(expense_id):
    #Gets the expense data based on the route parameter id and modefies it
    expense = Data.query.get(expense_id)
    if request.method == "POST":
        print(request.form.get("purpose"))
        purpose = request.form.get('purpose')
        cost = request.form.get("cost")
        expense.purpose= purpose
        expense.cost= cost
        db.session.commit()
        return redirect(url_for('all_data'))
    return render_template("Expense.html", expense=expense)

@app.route("/logout")
def logout():
    #loggs out
    logout_user()
    return redirect(url_for("home"))

# By default, when a script is executed, the interpreter reads the script and assigns the string __main__ to the __name__ keyword.
if __name__ == '__main__':
    app.run(debug = True)
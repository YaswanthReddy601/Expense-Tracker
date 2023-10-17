from flask_wtf import FlaskForm
from wtforms import SubmitField, IntegerField, StringField
from wtforms.validators import DataRequired

class RegisterForm(FlaskForm):
    name= StringField("name", validators=[DataRequired()])
    email= StringField("email", validators=[DataRequired()])
    password= StringField("password", validators=[DataRequired()])
    salary= IntegerField("salary", validators=[DataRequired()])
    submit= SubmitField("Submit")

class Login(FlaskForm):
    email= StringField("email", validators=[DataRequired()])
    password= StringField("password", validators=[DataRequired()])
    submit= SubmitField("submit")

class expenses(FlaskForm):
    purpose= StringField('purpose', validators=[DataRequired()])
    cost= StringField('cost', validators=[DataRequired()])
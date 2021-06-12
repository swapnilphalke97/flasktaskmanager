from flask import Flask, request, jsonify, render_template,redirect, url_for
import pickle
from flask_wtf import FlaskForm 
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_bootstrap import Bootstrap
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy  import SQLAlchemy
from datetime import datetime
from flask_login import  current_user

app = Flask(__name__)
app.config['SECRET_KEY'] = 'Thisissupposedtobesecret!'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///C:/Users/SWAPNIL/StockAPI/database.db'
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    todos=db.relationship('Todo',backref='owner')


class Todo(db.Model):
    id1 = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(200), nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    user_id=db.Column(db.String(200),db.ForeignKey('user.id'))
    def __repr__(self):
        return '<Task %r>' % self.id1

@app.route('/delete/<int:id1>')
def delete(id1):
    task_to_delete = Todo.query.get_or_404(id1)

    try:
        db.session.delete(task_to_delete)
        db.session.commit()
        return redirect('/expense')
    except:
        return 'There was a problem deleting that task'

@app.route('/update/<int:id1>', methods=['GET', 'POST'])
def update(id1):
    task = Todo.query.get_or_404(id1)

    if request.method == 'POST':
        task.content = request.form['content']

        try:
            db.session.commit()
            return redirect('/expense')
        except:
            return 'There was an issue updating your task'

    else:
        return render_template('expense.html', task=task)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
 
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('login'))
        #return '<h1>' + form.username.data + ' ' + form.email.data + ' ' + form.password.data + '</h1>'

    return render_template('signup.html', form=form)

@app.route('/expense', methods=['GET', 'POST'])
def expense():
    
    if request.method == 'POST':
        task_content = request.form['content']
        new_task = Todo(content=task_content,user_id=current_user.id)
        

       # try:
        db.session.add(new_task)
        db.session.commit()
        return redirect('/expense')
      #  except:
        #    return 'There was an issue adding your task'

    else:
        tasks = Todo.query.order_by(Todo.date_created).filter(Todo.user_id.contains(current_user.id)).all()
        return render_template('expense.html', tasks=tasks)


    
    def __repr__(self):
        return '<Task %r>' % self.id1


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')

class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])







@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('expense'))

        return '<h1>Invalid username or password</h1>'
        #return '<h1>' + form.username.data + ' ' + form.password.data + '</h1>'

    return render_template('login.html', form=form)



@app.route('/')
def index():
    return redirect(url_for('signup'))















if __name__ == "__main__":
    app.run(debug=True)

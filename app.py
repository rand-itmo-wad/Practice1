import os

from flask import Flask, render_template, request, url_for, redirect, session
import pymongo
import bcrypt
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = "Rand:)"
client = pymongo.MongoClient("mongodb://127.0.0.1:27017/")
db = client.get_database('ITMO')
records = db.users
notes_records = db.notes


@app.route('/')
def hello_world():  # put application's code here
    return redirect('/login')


@app.route('/home/<user>')
def hello(user):
    return render_template('index.html', user=user)


def auth_redirect():
    return redirect('/login')


@app.route('/signup', methods=['post', 'get'])
def signup():
    if "username" in session:
        return redirect("/profile")
    if request.method == "GET":
        return render_template('signup.html')
    else:
        user = request.form.get("username")
        password = request.form.get("password")

        if records.find_one({"username": user}):
            message = 'username already existed'
            return render_template('signup.html', message=message)
        else:
            password_hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            record = {'username': user, 'password': password_hashed}
            records.insert_one(record)
            session['username'] = user
            return redirect("/profile")


@app.route('/login', methods=['post', 'get'])
def login():
    if "username" in session:
        return redirect("/profile")
    if request.method == "GET":
        return render_template('login.html')
    else:
        user = request.form.get("username")
        password = request.form.get("password")

        user_record = records.find_one({"username": user})
        if user_record:
            user_password = user_record['password']
            if bcrypt.checkpw(password.encode('utf-8'), user_password):
                session['username'] = user
                return redirect('/profile')
        message = 'credentials not correct'
        return render_template('login.html', message=message)


ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/profile', methods=['GET', 'POST'])
def profile():
    message = None
    if session.get('username'):
        username = session['username']
        try:
            if records.find_one({"username": username})['picture']:
                filename = records.find_one({"username": username})['picture']
            else:
                filename = None
        except:
            filename = None
        if request.method == "POST":
            app_root = os.path.dirname(os.path.abspath(__file__))
            target = os.path.join(app_root, 'static/pictures')

            if not os.path.isdir(target):
                os.mkdir(target)

            filename = secure_filename(request.files.get("picture").filename)
            if request.files.get("picture") and allowed_file(filename):
                destination = os.path.join(target, filename)
                request.files.get("picture").save(destination)
                records.update_one({"username": username}, {"$set": {"picture": filename}})
                message = 'Image uploaded'
            else:
                try:
                    if records.find_one({"username": username})['picture']:
                        filename = records.find_one({"username": username})['picture']
                    else:
                        filename = None
                except:
                    filename = None
                message = 'Image extension is not allowed'
        return render_template('profile.html', destination=filename, message=message, username=username)
    else:
        return auth_redirect()


@app.route('/profile/notebook', methods=['GET', 'POST'])
def notebook():
    if session.get('username') == None:
        return auth_redirect()
    notes = notes_records.find({}, {'title': 1, 'description': 1})
    num = request.args.get('num', 0)
    num = int(num)
    if num > 0:
        notes.limit(num)
    username = session['username']
    user_record = records.find_one({"username": username})
    if request.method == "POST":
        title = request.form.get("title")
        description = request.form.get("description")

        record = {'title': title, 'description': description}
        notes_records.insert_one(record)

    return render_template('notebook.html', notes=notes)


@app.route('/profile/notebook/clear')
def notebook_clear():
    if session.get('username') == None:
        return auth_redirect()
    notes = notes_records.find({}, {'title': 1, 'description': 1})
    username = session['username']
    notes_records.delete_many({})
    return redirect('/profile/notebook')


@app.route('/display/<filename>', methods=['GET', 'POST'])
def display_image(filename):
    return redirect(url_for('static', filename='pictures/' + filename), code=301)


if __name__ == '__main__':
    app.run()

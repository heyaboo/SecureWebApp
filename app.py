
from flask import Flask, request, make_response, redirect, render_template, g, abort
from user_service import get_user_with_credentials, logged_in
from account_service import get_balance, do_transfer
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.config['SECRET_KEY'] = '3PPSWPEL5FNWBBSWKR'
csrf = CSRFProtect(app) 


@app.route("/", methods=['GET'])
def home():
    if not logged_in():
        return render_template("login.html")
    return redirect('/dashboard')


@app.route("/login", methods=["POST"])
def login():
    email = request.form.get("email")
    password = request.form.get("password")
    user = get_user_with_credentials(email, password)
    if not user:
        #XSS is prevented with the code below where we ensure that no script gets executed that is sent from this malicious user
        return render_template("login.html", error="Invalid credentials")
    response = make_response(redirect("/dashboard"))
    response.set_cookie("auth_token", user["token"])
    return response, 303


@app.route("/logout", methods=['GET'])
def logout():
    response = make_response(redirect("/dashboard"))

    #deleting cookie is very important to not allow other users who gain access to this computer access the bank account
    response.delete_cookie('auth_token')
    return response, 303


@app.route("/dashboard", methods=['GET'])
def dashboard():
    if not logged_in():
        return render_template("login.html")
    return render_template("dashboard.html", email=g.user)


@app.route("/details", methods=['GET', 'POST'])
def details():
    if not logged_in():
        return render_template("login.html")
    account_number = request.args['account']
    return render_template(
        "details.html", 
        user=g.user,
        account_number=account_number,
        balance = get_balance(account_number, g.user))


@app.route("/transfer", methods=["GET"])
def transfer_page():
    if not logged_in():
        return render_template("login.html")
    return render_template("transfer.html")


@app.route("/transfer", methods=["POST"])
def transfer():
    if not logged_in():
        return render_template("login.html")
    source = request.form.get("from")
    target = request.form.get("to")
    amount = int(request.form.get("amount"))

    #Below we are doing simple verification where users try to transfer money to themselves or
    #if they are trying to get transfer more than they actually have
    if amount < 0:
        abort(400, "Don't even think about it!")
    if amount > 1000:
        abort(400, "Seriously? Have some shame!")

    available_balance = get_balance(source, g.user)
    if available_balance is None:
        abort(404, "Account not found")
    if amount > available_balance:
        abort(400, "Insufficient funds")

    if do_transfer(source, target, amount):
        pass # TODO GIVE FEEDBACK
    else:
        abort(400, "Something bad happened")

    response = make_response(redirect("/dashboard"))
    return response, 303

    #What were considered here:
    #requests.args (requests for login details) is bad when you don't have templating system that prevents script injection. XXS vulnerability
    #brute force access to the account (hashing when password provided is wrong takes a long time on purpose!)
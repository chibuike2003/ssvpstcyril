from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import os
from functools import wraps
from sqlalchemy import func
import csv
from io import StringIO
from flask import Response


app = Flask(__name__)
app.secret_key = "secret_ssvp_key"

# --- CONFIGURATION ---
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///st.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# File Upload Settings
UPLOAD_FOLDER = 'static/uploads/receipts'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB Max Limit

# Ensure upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

db = SQLAlchemy(app)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- DECORATORS ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access this page.', 'error')
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_admin'):
            flash('Unauthorized Access. Admins Only.', 'error')
            return redirect(url_for('admin_login_page'))
        return f(*args, **kwargs)
    return decorated_function

# --- MODELS ---
class Member(db.Model):
    __tablename__ = 'members'
    id = db.Column(db.Integer, primary_key=True)
    fullname = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    password = db.Column(db.String(200), nullable=False)
    payments = db.relationship('Payment', backref='member', cascade="all, delete-orphan", lazy=True)

class Admin(db.Model):
    __tablename__ = 'admins'
    id = db.Column(db.Integer, primary_key=True)
    fullname = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    position = db.Column(db.String(50), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    birthday = db.Column(db.String(20), nullable=False)
    relationship_status = db.Column(db.String(30), nullable=False)
    address = db.Column(db.String(200), nullable=False)
    state = db.Column(db.String(50), nullable=False)
    lga = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(200), nullable=False)

class Payment(db.Model):
    __tablename__ = 'payments'
    id = db.Column(db.Integer, primary_key=True)
    member_id = db.Column(db.Integer, db.ForeignKey('members.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    months_paid = db.Column(db.String(200), nullable=False) 
    payment_date = db.Column(db.String(20), nullable=False)
    reference = db.Column(db.String(100), nullable=False)
    receipt_filename = db.Column(db.String(255), nullable=True) # New column
    status = db.Column(db.String(20), default="Pending")





# --- NEW MODEL: SECURITY ---
class Security(db.Model):
    __tablename__ = 'security'
    id = db.Column(db.Integer, primary_key=True)
    fullname = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)




# --- NEW MODEL: MASTER ---
class Master(db.Model):
    __tablename__ = 'masters'
    id = db.Column(db.Integer, primary_key=True)
    fullname = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    address = db.Column(db.String(200), nullable=False)
    purpose = db.Column(db.String(255), nullable=False)
    notes = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class ActivityLog(db.Model):
    __tablename__ = 'activity_logs'
    id = db.Column(db.Integer, primary_key=True)
    admin_name = db.Column(db.String(100))  # Static text (won't disappear)
    action = db.Column(db.String(255))      # Description of the task
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


# --- USER ROUTES ---
@app.route('/')
def home():
    return render_template('INDEX.html')

@app.route('/members-signup')
def members_page():
    if 'user_id' in session: return redirect(url_for('dashboard'))
    return render_template('users.html')

@app.route('/signup', methods=['POST'])
def signup():
    fullname = request.form.get('fullname')
    email = request.form.get('email')
    phone = request.form.get('phone')
    password = request.form.get('password')
    confirm_password = request.form.get('confirm_password')

    if Member.query.filter_by(email=email).first():
        flash('Email already registered!', 'error')
        return redirect(url_for('members_page'))

    if password != confirm_password:
        flash('Passwords do not match!', 'error')
        return redirect(url_for('members_page'))

    hashed_pw = generate_password_hash(password)
    new_member = Member(fullname=fullname, email=email, phone=phone, password=hashed_pw)

    try:
        db.session.add(new_member)
        db.session.commit()
        flash('Account created successfully!', 'success')
        return redirect(url_for('login_page'))
    except:
        db.session.rollback()
        flash('Database error.', 'error')
        return redirect(url_for('members_page'))

@app.route('/login')
def login_page():
    if 'user_id' in session: return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/login-submit', methods=['POST'])
def login_submit():
    identity = request.form.get('identity')
    password = request.form.get('password')
    member = Member.query.filter((Member.email == identity) | (Member.phone == identity)).first()

    if member and check_password_hash(member.password, password):
        session.permanent = True
        session['user_id'] = member.id
        session['user_name'] = member.fullname
        return redirect(url_for('dashboard')) 
    flash('Invalid credentials.', 'error')
    return redirect(url_for('login_page'))

@app.route('/dashboard')
@login_required
def dashboard():
    current_member = db.session.get(Member, session['user_id'])
    return render_template('usersdashboard.html', member=current_member)




@app.route('/edit-profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    # 1. Fetch the member from the database using the session ID
    member = db.session.get(Member, session['user_id'])
    
    if request.method == 'POST':
        # 2. Update the fields with the form data
        member.fullname = request.form.get('fullname')
        member.phone = request.form.get('phone')
        
        # 3. Handle optional password change
        new_password = request.form.get('new_password')
        if new_password and len(new_password) > 5:
            member.password = generate_password_hash(new_password)
        
        try:
            db.session.commit()
            # Update session name in case they changed it
            session['user_name'] = member.fullname 
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating profile: {str(e)}', 'error')

    # 4. GET request: Show the form with current data
    return render_template('edit_profile.html', member=member)


@app.route('/submit-dues', methods=['POST'])
@login_required
def submit_dues():
    member_id = session['user_id']
    amount = request.form.get('amount')
    reference = request.form.get('reference')
    selected_months = request.form.getlist('months') 
    
    if not selected_months:
        flash('Please select at least one month.', 'error')
        return redirect(url_for('dashboard'))

    # Handle File Upload
    file = request.files.get('receipt_file')
    filename = None
    if file and file.filename != '':
        if allowed_file(file.filename):
            ext = file.filename.rsplit('.', 1)[1].lower()
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = secure_filename(f"receipt_{member_id}_{timestamp}.{ext}")
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        else:
            flash('Invalid file type (JPG, PNG, PDF only).', 'error')
            return redirect(url_for('dashboard'))

    new_payment = Payment(
        member_id=member_id,
        amount=float(amount),
        months_paid=", ".join(selected_months),
        reference=reference,
        receipt_filename=filename,
        payment_date=datetime.now().strftime("%d %b, %Y"),
        status="Pending"
    )

    try:
        db.session.add(new_payment)
        db.session.commit()
        flash('Receipt submitted for approval!', 'success')
    except:
        db.session.rollback()
        flash('Submission error.', 'error')
    
    return redirect(url_for('dashboard'))




@app.route('/admin-signup')
def admin_signup_page():
    return render_template('admin.html')

@app.route('/admin-signup-submit', methods=['POST'])
def admin_signup_submit():
    # 1. Get data from form names
    fullname = request.form.get('fullname')
    email = request.form.get('email')
    password = request.form.get('password')
    confirm_password = request.form.get('confirm_password')

    # 2. Validation
    if Admin.query.filter_by(email=email).first():
        flash('Admin email already registered!', 'error')
        return redirect(url_for('admin_signup_page'))

    if password != confirm_password:
        flash('Passwords do not match!', 'error')
        return redirect(url_for('admin_signup_page'))

    # 3. Hash and Save
    hashed_pw = generate_password_hash(password)
    new_admin = Admin(
        fullname=fullname,
        email=email,
        position=request.form.get('position'),
        phone=request.form.get('phone'),
        birthday=request.form.get('birthday'),
        relationship_status=request.form.get('relationship_status'),
        address=request.form.get('address'),
        state=request.form.get('state'),
        lga=request.form.get('lga'),
        password=hashed_pw
    )

    try:
        db.session.add(new_admin)
        db.session.commit()
        flash('Admin account created! Please log in.', 'success')
        return redirect(url_for('admin_login_page'))
    except Exception as e:
        db.session.rollback()
        flash(f'Error: {str(e)}', 'error')
        return redirect(url_for('admin_signup_page'))



# --- ADMIN ROUTES ---
@app.route('/admin-login')
def admin_login_page():
    if 'admin_id' in session: return redirect(url_for('admin_dashboard'))
    return render_template('admin_login.html')

@app.route('/admin-login-submit', methods=['POST'])
def admin_login_submit():
    email = request.form.get('email')
    password = request.form.get('password')
    admin = Admin.query.filter_by(email=email).first()

    if admin and check_password_hash(admin.password, password):
        session.clear()
        session['admin_id'] = admin.id
        session['is_admin'] = True
        return redirect(url_for('admin_dashboard'))
    flash('Invalid Admin Credentials.', 'error')
    return redirect(url_for('admin_login_page'))

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    # 1. Identity Verification
    current_admin = db.session.get(Admin, session['admin_id'])
    
    # 2. Fetch Core Data Lists
    all_members = Member.query.all()
    all_payments = Payment.query.order_by(Payment.id.desc()).all() 
    all_masters = Master.query.order_by(Master.id.desc()).all() 

    # --- CALCULATIONS FOR SUMMARY CARDS ---
    
    # Financial: Sum of all 'Completed' payments
    total_collected = db.session.query(func.sum(Payment.amount))\
        .filter(Payment.status == 'Completed').scalar() or 0
    
    # Workflow: Count of payments waiting for approval
    pending_count = Payment.query.filter_by(status='Pending').count()
    
    # Impact: Count of Masters currently being assisted
    masters_count = Master.query.count()

    return render_template(
        'admindashboard.html', 
        admin=current_admin, 
        members=all_members, 
        payments=all_payments,
        masters=all_masters,
        total_collected=total_collected,
        pending_count=pending_count,
        masters_count=masters_count
    )


# --- NEW ROUTE: ADD MASTER ---
@app.route('/admin/add-master', methods=['POST'])
@admin_required
def add_master():
    fullname = request.form.get('fullname')
    phone = request.form.get('phone')
    address = request.form.get('address')
    purpose = request.form.get('purpose')
    notes = request.form.get('notes')

    if not fullname or not phone:
        flash('Name and Phone are required!', 'error')
        return redirect(url_for('admin_dashboard'))

    new_master = Master(
        fullname=fullname, 
        phone=phone, 
        address=address, 
        purpose=purpose, 
        notes=notes
    )

    try:
        db.session.add(new_master)
        db.session.commit()
        flash(f'Master {fullname} added to records.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error: {str(e)}', 'error')
    
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/logout')
def admin_logout():
    # Remove only admin-specific session data
    session.pop('admin_id', None)
    session.pop('is_admin', None)
    
    # Optional: Clear the entire session for maximum security
    # session.clear()
    
    flash('You have been logged out of the Admin Panel.', 'success')
    return redirect(url_for('admin_login_page'))


@app.route('/admin/add-user', methods=['POST'])
@admin_required
def admin_add_user():
    fullname = request.form.get('fullname')
    email = request.form.get('email')
    phone = request.form.get('phone')
    # Professional Tip: Set a default temporary password
    default_pw = generate_password_hash("ssvp1234")

    if Member.query.filter_by(email=email).first():
        flash('User with this email already exists!', 'error')
        return redirect(url_for('admin_dashboard'))

    new_member = Member(
        fullname=fullname, email=email, phone=phone,password=default_pw
    )

    try:
        db.session.add(new_member)
        db.session.commit()
        flash(f'User {fullname} created successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error: {str(e)}', 'error')
    
    return redirect(url_for('admin_dashboard'))



@app.route('/admin/edit-user/<int:user_id>', methods=['POST'])
@admin_required
def admin_edit_user(user_id):
    member = db.session.get(Member, user_id)
    if not member:
        flash('User not found!', 'error')
        return redirect(url_for('admin_dashboard'))

    # Update basic info
    member.fullname = request.form.get('fullname')
    member.email = request.form.get('email')
   
    # Handle Password Update
    new_password = request.form.get('new_password')
    if new_password and len(new_password) >= 6:
        member.password = generate_password_hash(new_password)
        flash(f'Profile and password for {member.fullname} updated!', 'success')
    else:
        flash('Profile updated successfully!', 'success')

    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        flash(f'Error: {str(e)}', 'error')
        
    return redirect(url_for('admin_dashboard'))
 


@app.route('/admin/delete-user/<int:user_id>')
@admin_required
def admin_delete_user(user_id):
    member = db.session.get(Member, user_id)
    if member:
        db.session.delete(member) # This triggers the cascade
        db.session.commit()
        flash('Member and their payment history deleted.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/verify-payment/<int:payment_id>/<string:action>')
@admin_required
def verify_payment(payment_id, action):
    payment = db.session.get(Payment, payment_id)
    if not payment:
        flash('Payment record not found.', 'error')
        return redirect(url_for('admin_dashboard'))

    if action == 'approve':
        payment.status = 'Completed'
        flash(f'Payment for {payment.member.fullname} approved!', 'success')
    elif action == 'decline':
        payment.status = 'Declined'
        flash(f'Payment for {payment.member.fullname} declined.', 'warning')

    db.session.commit()
    return redirect(url_for('admin_dashboard'))



def log_activity(action_text):
    # Try to get admin name from session; fallback to 'System'
    admin_name = session.get('user_name') or "Admin (ID: " + str(session.get('admin_id')) + ")"
    new_log = ActivityLog(admin_name=admin_name, action=action_text)
    db.session.add(new_log)
    db.session.commit()



@app.route('/logout')
def logout():
    session.clear() 
    return redirect(url_for('login_page'))






# --- SUPER ADMIN DECORATOR ---
def super_admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_super_admin'):
            flash('Root authorization required.', 'error')
            return redirect(url_for('super_login'))
        return f(*args, **kwargs)
    return decorated_function

# --- SUPER ADMIN ROUTES ---

@app.route('/super-register')
def super_register():
    return render_template('super_register.html') # The registration page you provided

@app.route('/super-register-submit', methods=['POST'])
def super_register_submit():
    fullname = request.form.get('fullname')
    email = request.form.get('email')
    password = request.form.get('password')
    confirm_password = request.form.get('confirm_password')

    if password != confirm_password:
        flash('Passwords do not match!', 'error')
        return redirect(url_for('super_register'))

    if Security.query.filter_by(email=email).first():
        flash('Super Admin already exists.', 'error')
        return redirect(url_for('super_register'))

    hashed_pw = generate_password_hash(password)
    new_super = Security(fullname=fullname, email=email, password=hashed_pw)
    
    db.session.add(new_super)
    db.session.commit()
    flash('Super Admin initialized successfully!', 'success')
    return redirect(url_for('super_login'))

@app.route('/super-login')
def super_login():
    return render_template('super_login.html')

@app.route('/super-login-submit', methods=['POST'])
def super_login_submit():
    email = request.form.get('email')
    password = request.form.get('password')
    super_user = Security.query.filter_by(email=email).first()

    if super_user and check_password_hash(super_user.password, password):
        session.clear() # Clear any existing regular admin/user sessions
        session['super_id'] = super_user.id
        session['is_super_admin'] = True
        session['user_name'] = super_user.fullname
        return redirect(url_for('super_dashboard'))
    
    flash('Invalid Root Credentials.')
    return redirect(url_for('super_login'))

@app.route('/super-dashboard')
@super_admin_required
def super_dashboard():
    # 1. Existing Counts
    admins_count = Admin.query.count()
    members_count = Member.query.count()
    
    # 2. Existing Revenue
    total_revenue = db.session.query(func.sum(Payment.amount))\
        .filter(Payment.status == 'Completed').scalar() or 0
    
    # 3. Existing Admin List
    all_admins = Admin.query.all()

    # --- ADD THIS LINE: Fetch the logs for the new table ---
    all_logs = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).limit(100).all()

    return render_template(
        'superadmindashboard.html', 
        admins_count=admins_count, 
        members_count=members_count, 
        total_revenue=total_revenue,
        all_admins=all_admins,
        logs=all_logs  # <-- Pass it to the template here
    )



@app.route('/super/download-logs')
@super_admin_required
def download_logs():
    si = StringIO()
    cw = csv.writer(si)
    
    # Header
    cw.writerow(['Date', 'Administrator', 'Action'])
    
    # Data
    logs = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).all()
    for log in logs:
        cw.writerow([log.timestamp.strftime('%Y-%m-%d %H:%M'), log.admin_name, log.action])
    
    output = si.getvalue()
    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-disposition": "attachment; filename=system_audit_logs.csv"}
    )


# ROUTE TO DELETE AN ADMIN
@app.route('/delete-admin/<int:admin_id>', methods=['POST'])
@super_admin_required
def delete_admin(admin_id):
    admin_to_delete = db.session.get(Admin, admin_id)
    if admin_to_delete:
        db.session.delete(admin_to_delete)
        db.session.commit()
        flash('Administrator access revoked.', 'success')
    return redirect(url_for('super_dashboard'))




@app.route('/super-logout')
def super_logout():
    # Clear only Super Admin related session data or everything for security
    session.pop('super_id', None)
    session.pop('is_super_admin', None)
    session.pop('user_name', None)
    
    # Or simply: session.clear() to be 100% safe
    
    flash('Root session terminated safely.', 'success')
    return redirect(url_for('super_login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
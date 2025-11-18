import os
import sys
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from datetime import datetime
from functools import wraps
# NEW IMPORT: Needed for counting stats
from sqlalchemy import func

# --- Configuration ---

# Get the URL from the cloud environment
db_url = os.environ.get('DATABASE_URL')

if db_url:
    # Fix for Render's Postgres URL format (postgres:// -> postgresql://)
    if db_url.startswith("postgres://"):
        db_url = db_url.replace("postgres://", "postgresql://", 1)
else:
    # Fallback to local file ONLY if no cloud URL is found
    db_url = 'sqlite:///test.db'

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a_very_secret_key_change_this')

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'


# --- Helper Functions ---

def admin_required(f):
    """
    Restricts access to Admin-only pages.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'Admin':
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def add_ticket_history(ticket, user, field, old_value, new_value):
    """
    Helper function to create a new TicketHistory entry.
    """
    if old_value == new_value:
        return
        
    history_entry = TicketHistory(
        bug_id=ticket.id,
        user_id=user.id,
        field=field,
        old_value=str(old_value),
        new_value=str(new_value)
    )
    db.session.add(history_entry)


# --- Database Models ---

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Association Tables
project_users = db.Table('project_users',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('project_id', db.Integer, db.ForeignKey('project.id'), primary_key=True)
)

ticket_developers = db.Table('ticket_developers',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('bug_id', db.Integer, db.ForeignKey('bug.id'), primary_key=True)
)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='Submitter')
    status = db.Column(db.String(20), nullable=False, default='Pending') 
    
    bugs_created = db.relationship('Bug', backref='author', lazy=True)
    projects = db.relationship('Project', secondary=project_users, lazy='subquery',
        backref=db.backref('team', lazy=True))

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    bugs = db.relationship('Bug', backref='project', lazy=True, cascade="all, delete-orphan")

    def __repr__(self):
        return f'<Project {self.name}>'

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    bug_id = db.Column(db.Integer, db.ForeignKey('bug.id'), nullable=False)
    author = db.relationship('User')

    def __repr__(self):
        return f'<Comment {self.id}>'
    
class TicketHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    field = db.Column(db.String(100), nullable=False)
    old_value = db.Column(db.String(255), nullable=True)
    new_value = db.Column(db.String(255), nullable=True)
    changed_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    bug_id = db.Column(db.Integer, db.ForeignKey('bug.id'), nullable=False)
    user = db.relationship('User')

    def __repr__(self):
        return f'<TicketHistory {self.id}: {self.field}>'

class Bug(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(20), nullable=False, default='New')
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)

    comments = db.relationship('Comment', backref='bug', lazy=True, cascade="all, delete-orphan")
    history = db.relationship('TicketHistory', backref='bug', lazy=True, cascade="all, delete-orphan")
    assigned_developers = db.relationship('User', secondary=ticket_developers, lazy='subquery',
        backref=db.backref('assigned_tickets', lazy=True))


# --- Authentication Routes ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        
        if user and user.check_password(password):
            if user.status != 'Approved':
                flash(f'Account not approved or is locked. Please contact admin.', 'danger')
                return redirect(url_for('login'))
                
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Login unsuccessful. Please check email and password.', 'danger')
            
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already registered.', 'danger')
            return redirect(url_for('register'))
            
        new_user = User(username=username, email=email, status='Pending')
        new_user.set_password(password)
        
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Account created! Please wait for admin approval.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash(f'Error creating account: {e}', 'danger')
            
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


# --- Application Routes ---

@app.route('/')
@login_required
def index():
    """
    Main page: Displays projects based on user role + Statistics.
    """
    users = [] 
    projects = []
    
    # 1. Fetch Projects based on Role
    if current_user.role == 'Admin':
        projects = Project.query.all()
        users = User.query.filter_by(status='Approved').all()
        
    elif current_user.role == 'ProjectManager':
        projects = current_user.projects
        
    elif current_user.role == 'Developer':
        projects = current_user.projects
        
    elif current_user.role == 'Submitter':
        projects = current_user.projects
    
    # 2. Calculate Statistics (Pie Chart & Bar Chart)
    
    # Get IDs of projects visible to this user
    visible_project_ids = [p.id for p in projects]
    
    # Default empty data
    pie_chart_data = {'labels': [], 'data': []}
    bar_chart_data = {'labels': [], 'data': []}
    
    if visible_project_ids:
        # Pie Chart: Count bugs by status
        bugs_by_status_query = db.session.query(
            Bug.status, func.count(Bug.id)
        ).filter(
            Bug.project_id.in_(visible_project_ids)
        ).group_by(
            Bug.status
        ).all()
        
        pie_chart_data['labels'] = [status for status, count in bugs_by_status_query]
        pie_chart_data['data'] = [count for status, count in bugs_by_status_query]
        
        # Bar Chart: Count bugs by project name
        bugs_by_project_query = db.session.query(
            Project.name, func.count(Bug.id)
        ).join(
            Bug, Project.id == Bug.project_id
        ).filter(
            Project.id.in_(visible_project_ids)
        ).group_by(
            Project.name
        ).order_by(
            Project.name
        ).all()
        
        bar_chart_data['labels'] = [name for name, count in bugs_by_project_query]
        bar_chart_data['data'] = [count for name, count in bugs_by_project_query]

    return render_template(
        'index.html', 
        projects=projects, 
        all_users=users,
        pie_chart_data=pie_chart_data,
        bar_chart_data=bar_chart_data
    )


@app.route('/project/create', methods=['POST'])
@login_required
@admin_required
def create_project():
    name = request.form.get('name')
    description = request.form.get('description')
    user_ids = request.form.getlist('team_members') 

    new_project = Project(name=name, description=description)
    
    if user_ids:
        team_members = User.query.filter(User.id.in_([int(uid) for uid in user_ids])).all()
        new_project.team.extend(team_members)
    
    try:
        db.session.add(new_project)
        db.session.commit()
        flash('New project created successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error creating project: {e}', 'danger')
        
    return redirect(url_for('index'))


@app.route('/project/<int:project_id>', methods=['GET', 'POST'])
@login_required
def project_detail(project_id):
    project = Project.query.get_or_404(project_id)
    
    if project not in current_user.projects and current_user.role != 'Admin':
        flash('You do not have access to this project.', 'danger')
        return redirect(url_for('index'))

    if request.method == 'POST':
        bug_title = request.form['title']
        bug_desc = request.form['description']
        
        new_bug = Bug(
            title=bug_title,
            description=bug_desc,
            status='New',
            user_id=current_user.id,
            project_id=project.id
        )
        
        try:
            db.session.add(new_bug)
            db.session.commit()
            flash('New ticket submitted!', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error submitting ticket: {e}', 'danger')
            
        return redirect(url_for('project_detail', project_id=project_id))
    
    else:
        tickets = Bug.query.filter_by(project_id=project.id).order_by(Bug.created_at.desc()).all()
        return render_template('project_detail.html', project=project, tickets=tickets)
    

@app.route('/ticket/<int:ticket_id>', methods=['GET', 'POST'])
@login_required
def ticket_detail(ticket_id):
    ticket = Bug.query.get_or_404(ticket_id)
    project = ticket.project
    
    if project not in current_user.projects and current_user.role != 'Admin':
        flash('You do not have access to this ticket.', 'danger')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        comment_body = request.form.get('body')
        if comment_body:
            new_comment = Comment(
                body=comment_body,
                user_id=current_user.id,
                bug_id=ticket.id
            )
            add_ticket_history(ticket, current_user, "Comment", "", "Added a new comment.")
            
            db.session.add(new_comment)
            db.session.commit()
            flash('Comment added.', 'success')
        
        return redirect(url_for('ticket_detail', ticket_id=ticket.id))

    project_team = project.team
    return render_template(
        'ticket_detail.html', 
        ticket=ticket, 
        project=project,
        project_team=project_team
    )


@app.route('/ticket/update/<int:ticket_id>', methods=['POST'])
@login_required
def update_ticket(ticket_id):
    ticket = Bug.query.get_or_404(ticket_id)
    project = ticket.project

    if project not in current_user.projects and current_user.role != 'Admin':
        flash('You do not have permission to modify this ticket.', 'danger')
        return redirect(url_for('ticket_detail', ticket_id=ticket.id))
        
    try:
        new_status = request.form.get('status')
        if new_status and new_status != ticket.status:
            add_ticket_history(ticket, current_user, "Status", ticket.status, new_status)
            ticket.status = new_status
            
        assigned_dev_ids = request.form.getlist('assigned_developers')
        old_dev_names = ", ".join(sorted([user.username for user in ticket.assigned_developers]))
        new_devs = User.query.filter(User.id.in_([int(uid) for uid in assigned_dev_ids])).all()
        new_dev_names = ", ".join(sorted([user.username for user in new_devs]))

        if old_dev_names != new_dev_names:
            add_ticket_history(ticket, current_user, "Assigned Team", old_dev_names, new_dev_names)
            ticket.assigned_developers = new_devs

        db.session.commit()
        flash('Ticket updated successfully.', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error updating ticket: {e}', 'danger')

    return redirect(url_for('ticket_detail', ticket_id=ticket.id))

@app.route('/assigned_tickets')
@login_required
def assigned_tickets():
    page_title = "My Assigned Tickets"
    tickets = []

    try:
        if current_user.role == 'Admin':
            page_title = "All Tickets (Admin)"
            tickets = Bug.query.order_by(Bug.created_at.desc()).all()
        
        elif current_user.role == 'ProjectManager':
            page_title = "My Projects' Tickets"
            project_ids = [project.id for project in current_user.projects]
            tickets = Bug.query.filter(Bug.project_id.in_(project_ids))\
                            .order_by(Bug.created_at.desc()).all()
        
        elif current_user.role == 'Developer':
            page_title = "Tickets Assigned to Me"
            tickets = current_user.assigned_tickets
            tickets.sort(key=lambda x: x.created_at, reverse=True)
            
        elif current_user.role == 'Submitter':
            page_title = "Tickets I Submitted"
            tickets = current_user.bugs_created
            tickets.sort(key=lambda x: x.created_at, reverse=True)

        return render_template('assigned_tickets.html', tickets=tickets, page_title=page_title)

    except Exception as e:
        flash(f'Error loading tickets: {e}', 'danger')
        return redirect(url_for('index'))


@app.route('/user_management')
@login_required
@admin_required
def user_management():
    try:
        users = User.query.order_by(User.id).all()
        return render_template('user_management.html', users=users)
    except Exception as e:
        flash(f'Error loading users: {e}', 'danger')
        return redirect(url_for('index'))

@app.route('/user/update/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def update_user(user_id):
    user_to_update = User.query.get_or_404(user_id)
    new_role = request.form.get('role')
    new_status = request.form.get('status')
    
    if user_to_update:
        user_to_update.role = new_role
        user_to_update.status = new_status
        try:
            db.session.commit()
            flash(f"User '{user_to_update.username}' updated successfully.", 'success')
        except Exception as e:
            db.session.rollback()
            flash(f"Error updating user: {e}", 'danger')
            
    return redirect(url_for('user_management'))

@app.route('/user/delete/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    user_to_delete = User.query.get_or_404(user_id)
    
    if user_to_delete.id == current_user.id:
        flash('You cannot delete your own admin account.', 'danger')
        return redirect(url_for('user_management'))

    try:
        db.session.delete(user_to_delete)
        db.session.commit()
        flash(f"User '{user_to_delete.username}' has been deleted.", 'success')
    except Exception as e:
        db.session.rollback()
        flash(f"Error deleting user: {e}", 'danger')
        
    return redirect(url_for('user_management'))

@app.route('/system_logs')
@login_required
@admin_required
def system_logs():
    try:
        logs = TicketHistory.query.order_by(TicketHistory.changed_at.desc()).all()
        return render_template('system_logs.html', logs=logs)
    except Exception as e:
        flash(f'Error loading system logs: {e}', 'danger')
        return redirect(url_for('index'))


# --- Main Execution / Admin Creation ---

def create_admin_user():
    """Helper function to create the default admin."""
    if not User.query.filter_by(email='admin@app.com').first():
        print("Creating default admin user...")
        admin_user = User(
            username='Admin',
            email='admin@app.com',
            role='Admin',
            status='Approved'
        )
        admin_user.set_password('password') 
        db.session.add(admin_user)
        db.session.commit()
        print("Admin user created.")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == 'create':
        print("Creating database tables...")
        with app.app_context():
            db.create_all()
            create_admin_user() 
        print("Database tables created successfully.")
    
    else:
        print("Starting local development server...")
        with app.app_context():
            db.create_all()
            create_admin_user()
        app.run(debug=True)

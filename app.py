import os
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from datetime import datetime
# Add this with your other imports
from functools import wraps

# --- Configuration ---
DATABASE_URL = os.environ.get('DATABASE_URL', 'sqlite:///test.db')

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'a_very_secret_key_change_this' # Change this!

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login' # Redirect to /login if not authenticated
login_manager.login_message_category = 'info'



# ... after login_manager setup

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


# --- Database Models ---

# This is the 'user_loader' callback for Flask-Login
# --- Database Models ---

# This is the 'user_loader' callback for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# vvv ADD THIS TABLE vvv
# This table is for the many-to-many relationship between Projects and Users
project_users = db.Table('project_users',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('project_id', db.Integer, db.ForeignKey('project.id'), primary_key=True)
)
ticket_developers = db.Table('ticket_developers',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('bug_id', db.Integer, db.ForeignKey('bug.id'), primary_key=True)
)
# ^^^ ADD THIS TABLE ^^^


class User(db.Model, UserMixin):
    """
    Represents a user in the system.
    """
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='Submitter')
    status = db.Column(db.String(20), nullable=False, default='Pending') 
    
    bugs_created = db.relationship('Bug', backref='author', lazy=True)
    
    # vvv ADD THIS RELATIONSHIP vvv
    # Links User to the projects they are assigned to
    projects = db.relationship('Project', secondary=project_users, lazy='subquery',
        backref=db.backref('team', lazy=True))
    # ^^^ ADD THIS RELATIONSHIP ^^^

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'


# vvv ADD THIS ENTIRE NEW MODEL vvv
class Project(db.Model):
    """
    Represents a project.
    """
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    # Links to bugs in this project
    bugs = db.relationship('Bug', backref='project', lazy=True, cascade="all, delete-orphan")

    def __repr__(self):
        return f'<Project {self.name}>'
# ^^^ ADD THIS ENTIRE NEW MODEL ^^^
class Comment(db.Model):
    """
    Represents a comment on a ticket.
    """
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    # ForeignKeys
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    bug_id = db.Column(db.Integer, db.ForeignKey('bug.id'), nullable=False)
    
    # Relationships
    author = db.relationship('User')

    def __repr__(self):
        return f'<Comment {self.id}>'
    
class TicketHistory(db.Model):
    """
    Represents an audit log entry for a ticket.
    """
    id = db.Column(db.Integer, primary_key=True)
    field = db.Column(db.String(100), nullable=False) # e.g., "Status", "Assigned Developer"
    old_value = db.Column(db.String(255), nullable=True)
    new_value = db.Column(db.String(255), nullable=True)
    changed_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    # ForeignKeys
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    bug_id = db.Column(db.Integer, db.ForeignKey('bug.id'), nullable=False)
    
    # Relationships
    user = db.relationship('User')

    def __repr__(self):
        return f'<TicketHistory {self.id}: {self.field}>'


class Bug(db.Model):
    """
    Represents a bug ticket in the tracker.
    """
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(20), nullable=False, default='New')
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)

    # vvv ADD THESE NEW RELATIONSHIPS vvv
    
    # Links to comments on this bug
    comments = db.relationship('Comment', backref='bug', lazy=True, cascade="all, delete-orphan")
    
    # Links to the history of this bug
    history = db.relationship('TicketHistory', backref='bug', lazy=True, cascade="all, delete-orphan")

    # Links to the developers assigned to this bug
    assigned_developers = db.relationship('User', secondary=ticket_developers, lazy='subquery',
        backref=db.backref('assigned_tickets', lazy=True))
    # ^^^ ADD THIS FOREIGN KEY ^^^

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
        
        # Check if user already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already registered.', 'danger')
            return redirect(url_for('register'))
            
        new_user = User(username=username, email=email, status='Pending') # 'Pending' as per your plan
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

# --- Application Routes ---

@app.route('/')
@login_required
def index():
    """
    Main page: Displays projects based on user role.
    """
    users = [] # For the 'New Project' modal
    
    if current_user.role == 'Admin':
        projects = Project.query.all()
        # Get all users to populate the 'assign team' list
        users = User.query.filter_by(status='Approved').all()
        
    elif current_user.role == 'ProjectManager':
        # Show projects this PM is assigned to
        projects = current_user.projects
        
    elif current_user.role == 'Developer':
        # Show projects this Developer is assigned to
        projects = current_user.projects
        
    elif current_user.role == 'Submitter':
        # Show projects this Submitter is assigned to
        projects = current_user.projects
        
    return render_template('index.html', projects=projects, all_users=users)


@app.route('/project/create', methods=['POST'])
@login_required
@admin_required
def create_project():
    """
    Handles creation of a new project (Admin only).
    """
    name = request.form.get('name')
    description = request.form.get('description')
    # Get the list of user IDs from the form's multi-select
    user_ids = request.form.getlist('team_members') 

    new_project = Project(name=name, description=description)
    
    # Find the user objects and add them to the project's team
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
    """
    Displays tickets for a specific project and handles new ticket creation.
    """
    project = Project.query.get_or_404(project_id)
    
    # --- Authorization Check ---
    # Ensure user is on the project team or is an Admin
    if project not in current_user.projects and current_user.role != 'Admin':
        flash('You do not have access to this project.', 'danger')
        return redirect(url_for('index'))

    if request.method == 'POST':
        # This is the "New Ticket" form submission
        bug_title = request.form['title']
        bug_desc = request.form['description']
        
        new_bug = Bug(
            title=bug_title,
            description=bug_desc,
            status='New',
            user_id=current_user.id,
            project_id=project.id  # Link bug to this project
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
        # GET request: Show the project's tickets
        tickets = Bug.query.filter_by(project_id=project.id).order_by(Bug.created_at.desc()).all()
        return render_template('project_detail.html', project=project, tickets=tickets)
    
    # --- Admin & User Management Routes ---

@app.route('/ticket/<int:ticket_id>', methods=['GET', 'POST'])
@login_required
def ticket_detail(ticket_id):
    """
    Displays the full ticket details page (Desc, Team, Comments, History).
    Handles POST requests for adding new comments.
    """
    ticket = Bug.query.get_or_404(ticket_id)
    project = ticket.project
    
    # --- Authorization Check ---
    if project not in current_user.projects and current_user.role != 'Admin':
        flash('You do not have access to this ticket.', 'danger')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        # This is a "New Comment" submission
        comment_body = request.form.get('body')
        if comment_body:
            new_comment = Comment(
                body=comment_body,
                user_id=current_user.id,
                bug_id=ticket.id
            )
            # Log this action
            add_ticket_history(ticket, current_user, "Comment", "", "Added a new comment.")
            
            db.session.add(new_comment)
            db.session.commit()
            flash('Comment added.', 'success')
        
        return redirect(url_for('ticket_detail', ticket_id=ticket.id))

    # GET Request:
    # Get all users on this ticket's project team to populate the "assign" list
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
    """
    Handles updates to a ticket's status, assigned developers, etc.
    """
    ticket = Bug.query.get_or_404(ticket_id)
    project = ticket.project

    # --- Authorization Check ---
    if project not in current_user.projects and current_user.role != 'Admin':
        flash('You do not have permission to modify this ticket.', 'danger')
        return redirect(url_for('ticket_detail', ticket_id=ticket.id))
        
    try:
        # --- Update Status ---
        new_status = request.form.get('status')
        if new_status and new_status != ticket.status:
            add_ticket_history(ticket, current_user, "Status", ticket.status, new_status)
            ticket.status = new_status
            
        # --- Update Assigned Developers ---
        assigned_dev_ids = request.form.getlist('assigned_developers')
        
        # Get a list of the *current* dev usernames for the log
        old_dev_names = ", ".join(sorted([user.username for user in ticket.assigned_developers]))
        
        # Get the new User objects
        new_devs = User.query.filter(User.id.in_([int(uid) for uid in assigned_dev_ids])).all()
        
        # Get a list of the *new* dev usernames for the log
        new_dev_names = ", ".join(sorted([user.username for user in new_devs]))

        # Check if the team has changed
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
    """
    Displays tickets based on the user's role:
    - Admin: All tickets
    - ProjectManager: Tickets from their projects
    - Developer: Tickets assigned to them
    - Submitter: Tickets they created
    """
    page_title = "My Assigned Tickets"
    tickets = []

    try:
        if current_user.role == 'Admin':
            page_title = "All Tickets (Admin)"
            tickets = Bug.query.order_by(Bug.created_at.desc()).all()
        
        elif current_user.role == 'ProjectManager':
            page_title = "My Projects' Tickets"
            # Get all project IDs this PM manages
            project_ids = [project.id for project in current_user.projects]
            # Get all tickets that belong to any of those projects
            tickets = Bug.query.filter(Bug.project_id.in_(project_ids))\
                            .order_by(Bug.created_at.desc()).all()
        
        elif current_user.role == 'Developer':
            page_title = "Tickets Assigned to Me"
            # Use the back-reference we created earlier
            tickets = current_user.assigned_tickets
            # We sort this in Python as it's a list, not a query
            tickets.sort(key=lambda x: x.created_at, reverse=True)
            
        elif current_user.role == 'Submitter':
            page_title = "Tickets I Submitted"
            # Use the back-reference we created
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
    """
    Display the user management page.
    """
    try:
        users = User.query.order_by(User.id).all()
        return render_template('user_management.html', users=users)
    except Exception as e:
        flash(f'Error loading users: {e}', 'danger')
        return redirect(url_for('index'))
def add_ticket_history(ticket, user, field, old_value, new_value):
    """
    Helper function to create a new TicketHistory entry.
    """
    # Don't log if the value hasn't actually changed
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

@app.route('/user/update/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def update_user(user_id):
    """
    Handle updating a user's role and status.
    """
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
    """
    Handle deleting a user.
    """
    user_to_delete = User.query.get_or_404(user_id)
    
    # Prevent admin from deleting themselves
    if user_to_delete.id == current_user.id:
        flash('You cannot delete your own admin account.', 'danger')
        return redirect(url_for('user_management'))

    try:
        # You'll need to decide what to do with bugs created by this user.
        # For now, we'll just delete the user.
        # A better approach later would be to re-assign their bugs or set user_id to null.
        
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
    """
    Displays the system-wide change tracker (audit log) for all tickets.
    (Admin Only)
    """
    try:
        # Fetch all history, most recent first
        logs = TicketHistory.query.order_by(TicketHistory.changed_at.desc()).all()
        return render_template('system_logs.html', logs=logs)
    except Exception as e:
        flash(f'Error loading system logs: {e}', 'danger')
        return redirect(url_for('index'))
# --- Run the App ---
# At the very end of app.py
# vvv REPLACE your old __name__ == "__main__" block with this vvv

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
        admin_user.set_password('password') # You can change the default password here
        db.session.add(admin_user)
        db.session.commit()
        print("Admin user created with email: admin@app.com, password: password")

if __name__ == "__main__":
    import sys
    
    # Check for a command-line argument
    if len(sys.argv) > 1 and sys.argv[1] == 'create':
        print("Creating database tables...")
        with app.app_context():
            db.create_all()
            create_admin_user() # Also create the admin user
        print("Database tables created successfully.")
    
    else:
        # This will run the app for local development
        print("Starting local development server...")
        with app.app_context():
            # Ensure tables and admin exist for local dev
            db.create_all()
            create_admin_user()
        app.run(debug=True)
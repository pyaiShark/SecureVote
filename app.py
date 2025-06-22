from flask import Flask, render_template, request, redirect, url_for, session, flash
from database import get_db, init_db, close_db
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import subprocess
import sqlite3
import os

def check_database_schema():

    if os.path.exists('migrate.py'):
        try:
            result = subprocess.run(['python', 'migrate.py'], capture_output=True, text=True)
            print("Migration output:")
            print(result.stdout)
            if result.stderr:
                print("Migration errors:")
                print(result.stderr)
        except Exception as e:
            print(f"Error running migration: {str(e)}")


check_database_schema()


app = Flask(__name__)
app.secret_key = os.urandom(24)

# Configure upload folder
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

# Create upload folder if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Initialize database
with app.app_context():
    init_db()

@app.teardown_appcontext
def close_connection(exception):
    close_db(exception)

@app.route('/logout')
def logout():
    # Clear the session data
    session.clear()
    flash('You have been logged out successfully', 'success')
    return redirect(url_for('login'))

# Login route 
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        voter_id = request.form['voter_id']
        password = request.form['password']
        
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT * FROM voters WHERE voter_id = ?", (voter_id,))
        voter = c.fetchone()
        
        if voter and check_password_hash(voter['password'], password):
            # Update last login time
            now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            try:
                c.execute("UPDATE voters SET last_login = ? WHERE id = ?", (now, voter['id']))
                conn.commit()
            except sqlite3.OperationalError as e:
                if "no such column" in str(e):
                    print("last_login column not found - run migrate.py")
                else:
                    print(f"Database error: {str(e)}")
            
            # Set session variables
            session['user_id'] = voter['id']
            session['voter_id'] = voter['voter_id']
            session['name'] = voter['name']
            session['has_voted'] = voter['has_voted']
            session['role'] = voter['role']
            session['last_login'] = now
            
            flash('Login successful!', 'success')
            
            # Redirect based on role
            if voter['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials. Please try again.', 'danger')
    
    return render_template('login.html')


# Main routes
@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db()
    c = conn.cursor()
    
    # Get all candidates
    c.execute("SELECT * FROM candidates")
    candidates = c.fetchall()
    
    # Get voter status
    has_voted = session.get('has_voted', False)
    
    return render_template('dashboard.html', 
                           candidates=candidates, 
                           has_voted=has_voted)

@app.route('/candidate/<int:candidate_id>')
def candidate_details(candidate_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db()
    c = conn.cursor()
    
    # Get candidate details
    c.execute("SELECT * FROM candidates WHERE id = ?", (candidate_id,))
    candidate = c.fetchone()
    
    # Get vote analytics
    c.execute("SELECT COUNT(*) as total_votes FROM votes")
    total_votes = c.fetchone()['total_votes'] or 0
    
    # Calculate vote share
    vote_share = round((candidate['votes'] / total_votes * 100), 1) if total_votes > 0 else 0
    
    # Get candidate rank
    c.execute("SELECT id, votes FROM candidates ORDER BY votes DESC")
    ranked_candidates = c.fetchall()
    rank = next((i+1 for i, cand in enumerate(ranked_candidates) if cand['id'] == candidate['id']), 1)
    
    return render_template('candidate.html', 
                           candidate=candidate, 
                           vote_share=vote_share,
                           rank=rank,
                           total_votes=total_votes)

@app.route('/vote/<int:candidate_id>', methods=['POST'])
def vote(candidate_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if session.get('has_voted'):
        flash('You have already voted!', 'warning')
        return redirect(url_for('dashboard'))
    
    conn = get_db()
    c = conn.cursor()
    
    try:
        # Record vote
        c.execute("INSERT INTO votes (voter_id, candidate_id) VALUES (?, ?)", 
                 (session['user_id'], candidate_id))
        
        # Update candidate vote count
        c.execute("UPDATE candidates SET votes = votes + 1 WHERE id = ?", (candidate_id,))
        
        # Mark voter as voted
        c.execute("UPDATE voters SET has_voted = 1 WHERE id = ?", (session['user_id'],))
        session['has_voted'] = True
        
        conn.commit()
        flash('Your vote has been recorded successfully!', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Error recording vote: {str(e)}', 'danger')
    
    return redirect(url_for('dashboard'))

@app.route('/results')
def results():
    conn = get_db()
    c = conn.cursor()
    
    # Get all candidates with votes
    c.execute("SELECT * FROM candidates ORDER BY votes DESC")
    candidates = c.fetchall()
    
    # Get total votes
    c.execute("SELECT COUNT(*) as total_votes FROM votes")
    total_votes = c.fetchone()['total_votes'] or 0
    
    # Calculate vote percentages
    for candidate in candidates:
        candidate = {
    'id': candidate['id'],
    'name': candidate['name'],
    'votes': candidate['votes'],
    'percentage': round((candidate['votes'] / total_votes * 100), 1) if total_votes > 0 else 0
}
    
    # Get precinct reporting percentage (simulated)
    precinct_reporting = 87
    
    return render_template('results.html', 
                           candidates=candidates,
                           total_votes=total_votes,
                           precinct_reporting=precinct_reporting)

# Admin routes
@app.route('/admin')
def admin_dashboard():

    # Check if user is logged in AND has admin role
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Unauthorized access. Admin privileges required.', 'danger')
        return redirect(url_for('login'))
    
    conn = get_db()
    c = conn.cursor()
    
    # Get stats
    c.execute("SELECT COUNT(*) as total_voters FROM voters")
    total_voters = c.fetchone()['total_voters']
    
    c.execute("SELECT COUNT(*) as voted_voters FROM voters WHERE has_voted = 1")
    voted_voters = c.fetchone()['voted_voters']
    
    c.execute("SELECT COUNT(*) as total_candidates FROM candidates")
    total_candidates = c.fetchone()['total_candidates']
    
    return render_template('admin/dashboard.html',
                           total_voters=total_voters,
                           voted_voters=voted_voters,
                           total_candidates=total_candidates)

@app.route('/admin/users')
def admin_users():
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Unauthorized access', 'danger')
        return redirect(url_for('login'))
    
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM voters")
    voters = c.fetchall()
    
    return render_template('admin/users.html', voters=voters)

@app.route('/admin/candidates')
def admin_candidates():
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Unauthorized access', 'danger')
        return redirect(url_for('login'))
    
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM candidates")
    candidates = c.fetchall()
    
    return render_template('admin/candidates.html', candidates=candidates)



@app.route('/admin/add_candidate', methods=['GET', 'POST'])
def add_candidate():
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Unauthorized access', 'danger')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        name = request.form['name']
        party = request.form['party']
        position = request.form['position']
        bio = request.form['bio']
        
        # Handle file upload
        photo = request.files['photo']
        photo_path = None
        
        if photo and photo.filename != '':
            if allowed_file(photo.filename):
                # Secure filename handling
                filename = secure_filename(f"candidate_{name}_{photo.filename}")
                save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                photo.save(save_path)
                photo_path = f"uploads/{filename}"  # Relative path for database
            else:
                flash('Invalid file type. Allowed: PNG, JPG, JPEG, GIF', 'danger')
                return render_template('admin/add_candidate.html')
        
        conn = get_db()
        c = conn.cursor()
        try:
            c.execute("INSERT INTO candidates (name, party, position, bio, photo) VALUES (?, ?, ?, ?, ?)",
                     (name, party, position, bio, photo_path))
            conn.commit()
            flash('Candidate added successfully!', 'success')
            return redirect(url_for('admin_candidates'))
        except Exception as e:
            conn.rollback()
            flash(f'Error adding candidate: {str(e)}', 'danger')
    
    return render_template('admin/add_candidate.html')

@app.route('/admin/add_user', methods=['GET', 'POST'])
def add_user():
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Unauthorized access', 'danger')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        name = request.form['name']
        voter_id = request.form['voter_id']
        password = request.form['password']
        role = request.form.get('role', 'voter')
        
        hashed_password = generate_password_hash(password)
        
        conn = get_db()
        c = conn.cursor()
        try:
            c.execute("INSERT INTO voters (name, voter_id, password, role) VALUES (?, ?, ?, ?)",
                     (name, voter_id, hashed_password, role))
            conn.commit()
            flash('User added successfully!', 'success')
            return redirect(url_for('admin_users'))
        except Exception as e:
            conn.rollback()
            flash(f'Error adding user: {str(e)}', 'danger')
    
    return render_template('admin/add_user.html')


# Edit User Route
@app.route('/admin/edit_user/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Unauthorized access', 'danger')
        return redirect(url_for('login'))
    
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM voters WHERE id = ?", (user_id,))
    user = c.fetchone()
    
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('admin_users'))
    
    if request.method == 'POST':
        name = request.form['name']
        voter_id = request.form['voter_id']
        role = request.form.get('role', 'voter')
        
        # Only update password if provided
        password = request.form['password']
        update_password = ''
        if password:
            hashed_password = generate_password_hash(password)
            update_password = ", password = ?"
        
        try:
            if update_password:
                c.execute(f"UPDATE voters SET name = ?, voter_id = ?, role = ? {update_password} WHERE id = ?",
                         (name, voter_id, role, hashed_password, user_id))
            else:
                c.execute("UPDATE voters SET name = ?, voter_id = ?, role = ? WHERE id = ?",
                         (name, voter_id, role, user_id))
            
            conn.commit()
            flash('User updated successfully!', 'success')
            return redirect(url_for('admin_users'))
        except Exception as e:
            conn.rollback()
            flash(f'Error updating user: {str(e)}', 'danger')
    
    return render_template('admin/edit_user.html', user=user)

# Edit Candidate Route
@app.route('/admin/edit_candidate/<int:candidate_id>', methods=['GET', 'POST'])
def edit_candidate(candidate_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Unauthorized access', 'danger')
        return redirect(url_for('login'))
    
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM candidates WHERE id = ?", (candidate_id,))
    candidate = c.fetchone()
    
    if not candidate:
        flash('Candidate not found', 'danger')
        return redirect(url_for('admin_candidates'))
    
    if request.method == 'POST':
        name = request.form['name']
        party = request.form['party']
        position = request.form['position']
        bio = request.form['bio']
        
        # Handle file upload
        photo = request.files['photo']
        photo_path = candidate['photo']  # Keep existing photo by default
        
        if photo and photo.filename != '':
            if allowed_file(photo.filename):
                # Delete old photo if exists
                if candidate['photo']:
                    old_photo_path = os.path.join(app.config['UPLOAD_FOLDER'], candidate['photo'].split('/')[-1])
                    if os.path.exists(old_photo_path):
                        os.remove(old_photo_path)
                
                # Save new photo
                filename = secure_filename(f"candidate_{name}_{photo.filename}")
                save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                photo.save(save_path)
                photo_path = f"uploads/{filename}"
            else:
                flash('Invalid file type. Allowed: PNG, JPG, JPEG, GIF', 'danger')
                return render_template('admin/edit_candidate.html', candidate=candidate)
        
        try:
            c.execute("UPDATE candidates SET name = ?, party = ?, position = ?, bio = ?, photo = ? WHERE id = ?",
                     (name, party, position, bio, photo_path, candidate_id))
            conn.commit()
            flash('Candidate updated successfully!', 'success')
            return redirect(url_for('admin_candidates'))
        except Exception as e:
            conn.rollback()
            flash(f'Error updating candidate: {str(e)}', 'danger')
    
    return render_template('admin/edit_candidate.html', candidate=candidate)


# Delete User Route
@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Unauthorized access', 'danger')
        return redirect(url_for('login'))
    
    conn = get_db()
    c = conn.cursor()
    
    try:
        # Check if user exists
        c.execute("SELECT * FROM voters WHERE id = ?", (user_id,))
        user = c.fetchone()
        
        if not user:
            flash('User not found', 'danger')
            return redirect(url_for('admin_users'))
        
        # Prevent deleting own account
        if user['id'] == session['user_id']:
            flash('You cannot delete your own account', 'danger')
            return redirect(url_for('admin_users'))
        
        # Delete user
        c.execute("DELETE FROM voters WHERE id = ?", (user_id,))
        conn.commit()
        flash('User deleted successfully', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Error deleting user: {str(e)}', 'danger')
    
    return redirect(url_for('admin_users'))

# Delete Candidate Route
@app.route('/admin/delete_candidate/<int:candidate_id>', methods=['POST'])
def delete_candidate(candidate_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Unauthorized access', 'danger')
        return redirect(url_for('login'))
    
    conn = get_db()
    c = conn.cursor()
    
    try:
        # Check if candidate exists
        c.execute("SELECT * FROM candidates WHERE id = ?", (candidate_id,))
        candidate = c.fetchone()
        
        if not candidate:
            flash('Candidate not found', 'danger')
            return redirect(url_for('admin_candidates'))
        
        # Delete candidate photo if exists
        if candidate['photo']:
            photo_path = os.path.join(app.config['UPLOAD_FOLDER'], candidate['photo'].split('/')[-1])
            if os.path.exists(photo_path):
                os.remove(photo_path)
        
        # Delete candidate
        c.execute("DELETE FROM candidates WHERE id = ?", (candidate_id,))
        conn.commit()
        flash('Candidate deleted successfully', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Error deleting candidate: {str(e)}', 'danger')
    
    return redirect(url_for('admin_candidates'))

# Profile Route
@app.route('/profile')
def profile():
    if 'user_id' not in session:
        flash('Please login to view your profile', 'danger')
        return redirect(url_for('login'))
    
    conn = get_db()
    c = conn.cursor()
    
    try:
        c.execute("SELECT * FROM voters WHERE id = ?", (session['user_id'],))
        user = c.fetchone()
    except sqlite3.OperationalError as e:
        if "no such column" in str(e):
            print("Database schema outdated - run migrate.py")
            flash('System maintenance in progress. Please try again later.', 'danger')
            return redirect(url_for('dashboard'))
        else:
            raise e
    
    # Handle missing last_login in database
    last_login = user['last_login'] or session['last_login'] or 'Never'
    
    return render_template('profile.html', user=user, last_login=last_login)

# Change Password Route
@app.route('/change_password', methods=['POST'])
def change_password():
    if 'user_id' not in session:
        flash('Please login to change your password', 'danger')
        return redirect(url_for('login'))
    
    current_password = request.form['current_password']
    new_password = request.form['new_password']
    confirm_password = request.form['confirm_password']
    
    # Validate inputs
    if not current_password or not new_password or not confirm_password:
        flash('All fields are required', 'danger')
        return redirect(url_for('profile'))
    
    if new_password != confirm_password:
        flash('New passwords do not match', 'danger')
        return redirect(url_for('profile'))
    
    if len(new_password) < 8:
        flash('Password must be at least 8 characters long', 'danger')
        return redirect(url_for('profile'))
    
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT password FROM voters WHERE id = ?", (session['user_id'],))
    db_password = c.fetchone()['password']
    
    # Verify current password
    if not check_password_hash(db_password, current_password):
        flash('Current password is incorrect', 'danger')
        return redirect(url_for('profile'))
    
    # Update password
    hashed_password = generate_password_hash(new_password)
    try:
        c.execute("UPDATE voters SET password = ? WHERE id = ?", 
                 (hashed_password, session['user_id']))
        conn.commit()
        flash('Password updated successfully!', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Error updating password: {str(e)}', 'danger')
    
    return redirect(url_for('profile'))


@app.template_filter('format_datetime')
def format_datetime_filter(value, format='%b %d, %Y %I:%M %p'):
    if isinstance(value, str):
        try:
            value = datetime.strptime(value, '%Y-%m-%d %H:%M:%S')
        except:
            return value
    if value is None:
        return ""
    return value.strftime(format)

if __name__ == '__main__':
    app.run(debug=True)
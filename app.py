from flask import Flask, render_template, request, redirect, url_for, flash
from database import create_connection, close_connection, prepare_query_value, process_result_value
import os
import re
import logging
import hashlib
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Change this for production

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database configuration
DATABASE = 'malware_db.sqlite'

# File upload configuration
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'exe', 'dll', 'msi', 'bat', 'ps1', 'js', 'vbs', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'pdf'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def calculate_file_hashes(filepath):
    """Calculate MD5 and SHA256 hashes for a file"""
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    
    try:
        with open(filepath, 'rb') as f:
            while chunk := f.read(8192):
                md5.update(chunk)
                sha256.update(chunk)
        return md5.hexdigest(), sha256.hexdigest()
    except Exception as e:
        logger.error(f"Error calculating hashes: {str(e)}")
        return None, None

def is_valid_hash(hash_value):
    """Validate hash format with strict checks (without quotes)"""
    if not isinstance(hash_value, str):
        return False
    
    hash_value = hash_value.strip().lower()
    
    # MD5: exactly 32 hex chars
    if re.fullmatch(r'^[a-f0-9]{32}$', hash_value):
        return 'md5'
    
    # SHA256: exactly 64 hex chars
    if re.fullmatch(r'^[a-f0-9]{64}$', hash_value):
        return 'sha256'
    
    return False

def get_malware_by_hash(hash_value):
    """Query malware by hash with proper quote handling"""
    hash_type = is_valid_hash(hash_value)
    if not hash_type:
        logger.warning(f"Invalid hash format: {hash_value}")
        return None
    
    conn = None
    try:
        conn = create_connection(DATABASE)
        if not conn:
            logger.error("Failed to establish database connection")
            return None
        
        # Prepare the hash value with quotes for querying
        quoted_hash = prepare_query_value(hash_value)
        
        if hash_type == 'md5':
            query = "SELECT * FROM full WHERE md5_hash = ?"
        else:
            query = "SELECT * FROM full WHERE sha256_hash = ?"
        
        logger.info(f"Executing query for {hash_type.upper()} hash: {quoted_hash}")
        
        cursor = conn.cursor()
        cursor.execute(query, (quoted_hash,))
        result = cursor.fetchone()
        
        if result:
            logger.info(f"Found malware record for hash: {hash_value}")
            # Process all result values to remove quotes
            return {key: process_result_value(value) for key, value in dict(result).items()}
        else:
            logger.info(f"No malware found for hash: {hash_value}")
            return None
    
    except sqlite3.OperationalError as e:
        logger.error(f"Database operational error: {str(e)}")
        if "no such table" in str(e).lower():
            return "DATABASE_ERROR: Table 'full' not found"
        elif "no such column" in str(e).lower():
            return "DATABASE_ERROR: Column not found"
        return "DATABASE_ERROR: Operational error"
    except Exception as e:
        logger.error(f"Unexpected error during query: {str(e)}")
        return "DATABASE_ERROR: Unexpected error"
    finally:
        if conn:
            close_connection(conn)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        # Check if the post request has the file part
        if 'file' in request.files:
            file = request.files['file']
            if file.filename == '':
                flash('No selected file')
                return redirect(request.url)
            
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                
                # Calculate hashes
                md5_hash, sha256_hash = calculate_file_hashes(filepath)
                
                # Clean up uploaded file
                try:
                    os.remove(filepath)
                except Exception as e:
                    logger.error(f"Error deleting uploaded file: {str(e)}")
                
                if not md5_hash or not sha256_hash:
                    return render_template('result.html',
                                         hash="File upload error",
                                         error="Could not calculate file hashes")
                
                # Check both hashes
                malware_info = get_malware_by_hash(sha256_hash) or get_malware_by_hash(md5_hash)
                
                return render_template('result.html',
                                     hash=f"SHA256: {sha256_hash}\nMD5: {md5_hash}",
                                     filename=filename,
                                     malware=malware_info)
            else:
                flash('File type not allowed')
                return redirect(request.url)
        
        # Handle hash submission
        hash_value = request.form.get('hash', '').strip()
        if hash_value:
            if not is_valid_hash(hash_value):
                return render_template('result.html',
                                   hash=hash_value,
                                   error="Invalid hash format. Must be 32 chars (MD5) or 64 chars (SHA256) hexadecimal.")
            
            malware_info = get_malware_by_hash(hash_value)
            
            if isinstance(malware_info, str) and malware_info.startswith("DATABASE_ERROR:"):
                return render_template('result.html',
                                   hash=hash_value,
                                   error=malware_info.replace("DATABASE_ERROR:", "Database Error:").strip())
            
            return render_template('result.html',
                                 hash=hash_value,
                                 malware=malware_info)
        
        return redirect(url_for('index'))
    
    return render_template('index.html')

if __name__ == '__main__':
    # Check if database exists
    if not os.path.exists(DATABASE):
        logger.error(f"Database file not found: {DATABASE}")
        print(f"ERROR: Database file not found at {DATABASE}")
    else:
        logger.info(f"Database file exists: {DATABASE}")
    
    app.run(debug=True, host='0.0.0.0', port=5000)

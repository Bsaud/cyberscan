import sqlite3
from sqlite3 import Error
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def create_connection(db_file):
    """Create a database connection to the SQLite database"""
    conn = None
    try:
        conn = sqlite3.connect(db_file)
        conn.row_factory = sqlite3.Row  # Access columns by name
        logger.info(f"Successfully connected to database: {db_file}")
        return conn
    except Error as e:
        logger.error(f"Database connection failed: {str(e)}")
        return None
    except Exception as e:
        logger.error(f"Unexpected connection error: {str(e)}")
        return None

def close_connection(conn):
    """Safely close database connection"""
    try:
        if conn:
            conn.close()
            logger.info("Database connection closed")
    except Exception as e:
        logger.error(f"Error closing connection: {str(e)}")

def prepare_query_value(value):
    """Prepare values for querying by adding quotes if needed"""
    if value is None:
        return None
    value = str(value).strip()
    if not (value.startswith('"') and value.endswith('"')):
        return f'"{value}"'
    return value

def process_result_value(value):
    """Process result values by removing surrounding quotes"""
    if value is None:
        return None
    value = str(value).strip()
    if value.startswith('"') and value.endswith('"'):
        return value[1:-1]
    return value

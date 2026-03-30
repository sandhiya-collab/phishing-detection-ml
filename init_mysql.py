# init_mysql.py
from app import app, db
from config import SQLALCHEMY_DATABASE_URI
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def init_database():
    """Initialize MySQL database with all tables"""
    try:
        with app.app_context():
            logger.info("Creating database tables...")
            db.create_all()
            logger.info("✅ All tables created successfully!")
            
            # Verify tables were created
            from sqlalchemy import inspect
            inspector = inspect(db.engine)
            tables = inspector.get_table_names()
            logger.info(f"📊 Tables created: {', '.join(tables)}")
            
    except Exception as e:
        logger.error(f"❌ Error creating tables: {e}")
        raise

if __name__ == "__main__":
    init_database()
from app import app, db, user_datastore

def init_database():
    with app.app_context():
        db.create_all()
        
        # Create default roles if they don't exist
        if not user_datastore.find_role('user'):
            user_datastore.create_role(name='user', description='Regular user role')
        if not user_datastore.find_role('admin'):
            user_datastore.create_role(name='admin', description='Administrator role')
            
        db.session.commit()
        print("Database initialized successfully!")

if __name__ == "__main__":
    init_database()
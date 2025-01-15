from sqlalchemy import create_engine

DATABASE_URI = "mysql+pymysql://root:Xolani40201@localhost/grade12support"
engine = create_engine(DATABASE_URI)

try:
    connection = engine.connect()
    print("Connection successful!")
    connection.close()
except Exception as e:
    print(f"Connection failed: {e}")

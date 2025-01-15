from doctest import debug
import os
from users import create_app

config_type = os.getenv("FLASK_ENV", "development")

app = create_app(config_type)

if __name__ == "__main__":
    app.run()
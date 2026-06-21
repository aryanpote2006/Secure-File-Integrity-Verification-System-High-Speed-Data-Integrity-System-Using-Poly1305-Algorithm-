from pathlib import Path

from flask import Flask

from config import Config


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    Path(app.config["UPLOAD_FOLDER"]).mkdir(parents=True, exist_ok=True)

    from .db import init_app
    from .routes import bp

    init_app(app)
    app.register_blueprint(bp)
    return app

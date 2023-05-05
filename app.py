from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
#from geoalchemy2 import Geometry
from flasgger import Swagger, swag_from
from flask_cors import CORS

app = Flask(__name__)
CORS(app)
swagger = Swagger(app, template={
    "swagger": "2.0",
    "info": {
        "title": "Camera API",
        "version": "1.0",
        "description": "API for managing cameras",
    },
    "basePath": "/",
    "schemes": [
        "http",
        "https"
    ],
    "securityDefinitions": {
        "Bearer": {
            "type": "apiKey",
            "name": "/Authorization",
            "in": "header"
        }
    },
    "security": [
        {"Bearer": []}
    ],
    "produces": [
        "application/json"
    ]
})

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'

db = SQLAlchemy(app)
jwt = JWTManager(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

class Camera(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(15), nullable=False)
    port = db.Column(db.Integer, nullable=False)
    analysis = db.Column(db.Boolean, nullable=False)
    store_video = db.Column(db.Boolean, nullable=False)
    weather_removal = db.Column(db.Boolean, nullable=False)
    name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=True)
    #geolocation = db.Column(Geometry("POINT"), nullable=False)

#### USER BYSINESS LOGIC ####
@app.route('/register', methods=['POST'])
@swag_from({
    'tags': ['User'],
    'parameters': [
        {
            'name': 'user',
            'in': 'body',
            'required': 'true',
            'schema': {
                'type': 'object',
                'properties': {
                    'name': {'type': 'string'},
                    'password': {'type': 'string'}
                }
            }
        }
    ],
    'responses': {
        '201': {'description': 'User registered successfully.'},
        '409': {'description': 'User already exists.'}
    }
})
def register():
    data = request.get_json()
    username = data['name']
    password = data['password']

    user = User.query.filter_by(username=username).first()

    if user:
        return jsonify({'message': 'User already exists.'}), 409

    hashed_password = generate_password_hash(password, method='sha256')

    new_user = User(username=username, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully.'}), 201


@app.route('/login', methods=['POST'])
@swag_from({
    'tags': ['User'],
    'parameters': [
        {
            'name': 'credentials',
            'in': 'body',
            'required': 'true',
            'schema': {
                'type': 'object',
                'properties': {
                    'name': {'type': 'string'},
                    'password': {'type': 'string'}
                }
            }
        }
    ],
    'responses': {
        '200': {'description': 'Login successful.'},
        '401': {'description': 'Invalid credentials.'}
    }
})
def login():
    data = request.get_json()
    username = data['name']
    password = data['password']

    user = User.query.filter_by(username=username).first()

    if not user or not check_password_hash(user.password, password):
        return jsonify({'message': 'Invalid credentials.'}), 401

    access_token = create_access_token(identity=user.id)
    return jsonify({'access_token': access_token})


@app.route('/logout', methods=['POST'])
@jwt_required()
@swag_from({
    'tags': ['User'],
    'responses': {
        '200': {'description': 'User logged out.'}
    }
})
def logout():
    jwt_id = get_jwt_identity()
    return jsonify({'message': f'User {jwt_id} has logged out.'}), 200

#### CAMERA BYSINESS LOGIC ####
@app.route('/cameras', methods=['POST'])
@jwt_required()
@swag_from({
    'tags': ['Camera'],
    'parameters': [
        {
            'name': 'camera',
            'in': 'body',
            'required': 'true',
            'schema': {
                'type': 'object',
                'properties': {
                    'ip_address': {'type': 'string'},
                    'port': {'type': 'integer'},
                    'analysis': {'type': 'boolean'},
                    'store_video': {'type': 'boolean'},
                    'weather_removal': {'type': 'boolean'},
                    'name': {'type': 'string'},
                    'description': {'type': 'string'}
                }
            }
        }
    ],
    'responses': {
        '201': {'description': 'Camera created successfully.'},
        '400': {'description': 'Bad request.'},
    }
})
def create_camera():
    data = request.get_json()

    new_camera = Camera(
        ip_address=data['ip_address'],
        port=data['port'],
        analysis=data['analysis'],
        store_video=data['store_video'],
        weather_removal=data['weather_removal'],
        name=data['name'],
        description=data['description']
    )

    db.session.add(new_camera)
    db.session.commit()

    return jsonify({'message': 'Camera created successfully.'}), 201

@app.route('/cameras', methods=['GET'])
@jwt_required()
@swag_from({
    'tags': ['Camera'],
    'responses': {
        '200': {
            'description': 'List of all cameras.',
            'schema': {
                'type': 'object',
                'properties': {
                    'cameras': {
                        'type': 'array',
                        'items': {'$ref': '#/definitions/Camera'}
                    }
                }
            }
        }
    }
})
def get_cameras():
    cameras = Camera.query.all()
    output = []

    for camera in cameras:
        output.append({
            'id': camera.id,
            'ip_address': camera.ip_address,
            'port': camera.port,
            'analysis': camera.analysis,
            'store_video': camera.store_video,
            'weather_removal': camera.weather_removal,
            'name': camera.name,
            'description': camera.description
        })

    return jsonify({'cameras': output})

@app.route('/cameras/<int:camera_id>', methods=['GET'])
@jwt_required()
@swag_from({
    'tags': ['Camera'],
    'parameters': [
        {
            'name': 'camera_id',
            'in': 'path',
            'type': 'integer',
            'required': 'true',
            'description': 'ID of the camera to retrieve.'
        }
    ],
    'responses': {
        '200': {
            'description': 'Camera details.',
            'schema': {'$ref': '#/definitions/Camera'}
        },
        '404': {'description': 'Camera not found.'}
    }
})
def get_camera(camera_id):
    camera = Camera.query.get_or_404(camera_id)
    return jsonify({
        'id': camera.id,
        'ip_address': camera.ip_address,
        'port': camera.port,
        'analysis': camera.analysis,
        'store_video': camera.store_video,
        'weather_removal': camera.weather_removal,
        'name': camera.name,
        'description': camera.description
    })

@app.route('/cameras/<int:camera_id>', methods=['PUT'])
@jwt_required()
@swag_from({
    'tags': ['Camera'],
    'parameters': [
        {
            'name': 'camera_id',
            'in': 'path',
            'type': 'integer',
            'required': 'true',
            'description': 'ID of the camera to update.'
        },
        {
            'name': 'camera',
            'in': 'body',
            'required': 'true',
            'schema': {'$ref': '#/definitions/Camera'}
        }
    ],
    'responses': {
        '200': {'description': 'Camera updated successfully.'},
        '404': {'description': 'Camera not found.'},
    }
})
def update_camera(camera_id):
    data = request.get_json()
    camera = Camera.query.get_or_404(camera_id)

    camera.ip_address = data['ip_address']
    camera.port = data['port']
    camera.analysis = data['analysis']
    camera.store_video = data['store_video']
    camera.weather_removal = data['weather_removal']
    camera.name = data['name']
    camera.description = data['description']

    db.session.commit()

    return jsonify({'message': 'Camera updated successfully.'})

@app.route('/cameras/<int:camera_id>', methods=['DELETE'])
@jwt_required()
@swag_from({
    'tags': ['Camera'],
    'parameters': [
        {
            'name': 'camera_id',
            'in': 'path',
            'type': 'integer',
            'required': 'true',
            'description': 'ID of the camera to delete.'
        }
    ],
    'responses': {
        '200': {'description': 'Camera deleted successfully.'},
        '404': {'description': 'Camera not found.'},
    }
})
def delete_camera(camera_id):
    camera = Camera.query.get_or_404(camera_id)
    db.session.delete(camera)
    db.session.commit()
    return jsonify({'message': 'Camera deleted successfully.'})


if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)

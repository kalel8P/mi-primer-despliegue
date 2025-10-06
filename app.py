
Import os
# Import necessary libraries
from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from geopy.distance import geodesic  # For calculating distances
import uuid  # For generating unique request IDs
from datetime import datetime

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.envir  # Change this to a secure random key
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('SECRET_KEY','default_secret')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Database Models

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    is_provider = db.Column(db.Boolean, default=False)  # True if provider, False if client
    location_lat = db.Column(db.Float)  # Current latitude
    location_lon = db.Column(db.Float)  # Current longitude
    available = db.Column(db.Boolean, default=False)  # For providers: availability status

class ServiceRequest(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    client_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    provider_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    request_time = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='pending')  # pending, accepted, completed, cancelled
    client_lat = db.Column(db.Float, nullable=False)
    client_lon = db.Column(db.Float, nullable=False)
    description = db.Column(db.Text)  # Optional description of the issue

# Create database tables
with app.app_context():
    db.create_all()

# Helper function to check if user is logged in
def is_logged_in():
    return 'user_id' in session

# Routes

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')
    is_provider = data.get('is_provider', False)

    if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
        return jsonify({'error': 'User already exists'}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(username=username, password=hashed_password, email=email, is_provider=is_provider)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()
    if user and bcrypt.check_password_hash(user.password, password):
        session['user_id'] = user.id
        return jsonify({'message': 'Logged in successfully', 'is_provider': user.is_provider}), 200
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)
    return jsonify({'message': 'Logged out successfully'}), 200

@app.route('/update_location', methods=['POST'])
def update_location():
    if not is_logged_in():
        return jsonify({'error': 'Not logged in'}), 401

    data = request.json
    lat = data.get('lat')
    lon = data.get('lon')

    user = User.query.get(session['user_id'])
    user.location_lat = lat
    user.location_lon = lon
    db.session.commit()

    return jsonify({'message': 'Location updated'}), 200

@app.route('/set_availability', methods=['POST'])
def set_availability():
    if not is_logged_in():
        return jsonify({'error': 'Not logged in'}), 401

    user = User.query.get(session['user_id'])
    if not user.is_provider:
        return jsonify({'error': 'Not a provider'}), 403

    data = request.json
    available = data.get('available', False)
    user.available = available
    db.session.commit()

    return jsonify({'message': 'Availability updated'}), 200

@app.route('/request_service', methods=['POST'])
def request_service():
    if not is_logged_in():
        return jupytext({'error': 'Not logged in'}), 401

    user = User.query.get(session['user_id'])
    if user.is_provider:
        return jsonify({'error': 'Providers cannot request services'}), 403

    data = request.json
    lat = data.get('lat')
    lon = data.get('lon')
    description = data.get('description', '')

    new_request = ServiceRequest(client_id=user.id, client_lat=lat, client_lon=lon, description=description)
    db.session.add(new_request)
    db.session.commit()

    return jsonify({'message': 'Service requested', 'request_id': new_request.id}), 201

@app.route('/get_available_requests', methods=['GET'])
def get_available_requests():
    if not is_logged_in():
        return jsonify({'error': 'Not logged in'}), 401

    user = User.query.get(session['user_id'])
    if not user.is_provider or not user.available:
        return jsonify({'error': 'Not an available provider'}), 403

    # Get pending requests
    pending_requests = ServiceRequest.query.filter_by(status='pending').all()

    # Filter and sort by distance
    user_location = (user.location_lat, user.location_lon)
    requests_with_distance = []
    for req in pending_requests:
        req_location = (req.client_lat, req.client_lon)
        distance = geodesic(user_location, req_location).km
        if distance <= 10:  # Arbitrary 10km radius; adjust as needed
            requests_with_distance.append({
                'request_id': req.id,
                'client_id': req.client_id,
                'distance_km': distance,
                'description': req.description,
                'request_time': req.request_time.isoformat()
            })

    # Sort by distance
    requests_with_distance.sort(key=lambda x: x['distance_km'])

    return jsonify({'requests': requests_with_distance}), 200

@app.route('/accept_request', methods=['POST'])
def accept_request():
    if not is_logged_in():
        return jsonify({'error': 'Not logged in'}), 401

    user = User.query.get(session['user_id'])
    if not user.is_provider:
        return jsonify({'error': 'Not a provider'}), 403

    data = request.json
    request_id = data.get('request_id')

    service_request = ServiceRequest.query.get(request_id)
    if not service_request or service_request.status != 'pending':
        return jsonify({'error': 'Invalid or already accepted request'}), 400

    service_request.provider_id = user.id
    service_request.status = 'accepted'
    db.session.commit()

    return jsonify({'message': 'Request accepted'}), 200

@app.route('/complete_request', methods=['POST'])
def complete_request():
    if not is_logged_in():
        return jsonify({'error': 'Not logged in'}), 401

    data = request.json
    request_id = data.get('request_id')

    service_request = ServiceRequest.query.get(request_id)
    if not service_request or service_request.status != 'accepted':
        return jsonify({'error': 'Invalid request or not accepted'}), 400

    if service_request.provider_id != session['user_id'] and service_request.client_id != session['user_id']:
        return jsonify({'error': 'Not authorized'}), 403

    service_request.status = 'completed'
    db.session.commit()

    return jsonify({'message': 'Request completed'}), 200

@app.route('/cancel_request', methods=['POST'])
def cancel_request():
    if not is_logged_in():
        return jsonify({'error': 'Not logged in'}), 401

    data = request.json
    request_id = data.get('request_id')

    service_request = ServiceRequest.query.get(request_id)
    if not service_request:
        return jsonify({'error': 'Invalid request'}), 400

    if service_request.client_id != session['user_id'] and (service_request.provider_id != session['user_id'] or service_request.status != 'accepted'):
        return jsonify({'error': 'Not authorized'}), 403

    service_request.status = 'cancelled'
    db.session.commit()

    return jsonify({'message': 'Request cancelled'}), 200

# Run the app
if __name__ == '__main__':
    app.run(debug=True)
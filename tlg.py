from flask import Flask, jsonify, request, Response
from sqlalchemy import create_engine, Column, Integer, String, DateTime, text
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.dialects.postgresql import ENUM
from datetime import datetime
from sqlalchemy.sql import func
import csv
from sqlalchemy.exc import IntegrityError
from io import TextIOWrapper
from functools import wraps
import logging
import yaml
import xml.etree.ElementTree as ET
from dicttoxml import dicttoxml
from math import ceil
from flasgger import Swagger


app = Flask(__name__)

# Database connection configuration
DB_HOST = 'localhost'
DB_NAME = 'postgres'
DB_USER = 'postgres'
DB_PASSWORD = 'Nchoudhary007'

# Define the SQLAlchemy engine
engine = create_engine(
    f'postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}/{DB_NAME}')
Session = sessionmaker(bind=engine)

# Define the base model
Base = declarative_base()

# Initialize Swagger
swagger = Swagger(app)
app.config['SWAGGER'] = {
    'title': 'Ticket API',
    'uiversion': 3
}

VALID_STATUSES = ['OPEN', 'WIP', 'SOLVED', 'STANDBY']
# Define the Status ENUM type
StatusEnum = ENUM('OPEN', 'WIP', 'SOLVED', 'STANDBY', name='status_enum')

# Define the Ticket model


class Ticket(Base):
    __tablename__ = 'tickets'

    id = Column(Integer, primary_key=True)
    subject = Column(String)
    language = Column(String, default='en')
    country = Column(String, default='US')
    status = Column(StatusEnum, default='OPEN')
    order_no = Column(String, nullable=False)
    timestamp = Column(DateTime, default=func.now())

# Define the User model


class User(Base):
    __tablename__ = 'users'

    id = Column(String, primary_key=True)
    username = Column(String)
    secret = Column(String)
    scopes = Column(String)
    access_token = Column(String)

    def __init__(self, username, id, secret, scopes):
        self.id = id
        self.username = username
        self.secret = secret
        self.scopes = scopes
        self.access_token = None


# Create the table schema
Base.metadata.create_all(engine)


@app.route('/oauth/token', methods=['POST'])
def access_token():
    username = request.form.get('username')
    password = request.form.get('password')

    session = Session()
    user = session.query(User).filter_by(username=username).first()
    session.close()

    logging.warning('user')
    logging.warning(user)
    if user and check_password_hash(user.secret, password):
        access_token = user.access_token
        if not access_token:
            # Generate a new access token if not already present
            access_token = generate_access_token()
            user.access_token = access_token
            session = Session()
            session.add(user)  # Add the user object to the session
            session.commit()  # Commit the changes to the database
            session.close()

        return jsonify({'access_token': access_token})

    return jsonify({'error': 'Invalid credentials'}), 401


def generate_access_token():
    # Generating a random access token
    import secrets
    return secrets.token_hex(16)


def require_oauth(scope):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            access_token = request.headers.get('Authorization')
            if not access_token:
                return jsonify({'error': 'Missing access token'}), 401

            access_token = access_token.replace('Bearer ', '')

            session = Session()
            user = session.query(User).filter_by(
                access_token=access_token).first()
            session.close()

            if not user:
                return jsonify({'error': 'Invalid access token'}), 401

            if scope not in user.scopes:
                return jsonify({'error': 'Insufficient scope'}), 403

            return f(*args, **kwargs)

        return decorated

    return decorator


def get_user_by_access_token(access_token):
    for user in User.values():
        if user.access_token == access_token:
            return user
    return None


@app.route('/tickets', methods=['GET'])
@require_oauth('READ')
def get_tickets():
    """
    Get tickets endpoint.
    ---
    security:
      - Bearer: []
    parameters:
      - name: id
        in: query
        type: integer
        description: Filter by ticket ID
      - name: subject
        in: query
        type: string
        description: Filter by subject
      - name: language
        in: query
        type: string
        description: Filter by language
      - name: country
        in: query
        type: string
        description: Filter by country
      - name: status
        in: query
        type: string
        description: Filter by status
      - name: order_no
        in: query
        type: string
        description: Filter by order number
      - name: minDate
        in: query
        type: string
        description: Filter by minimum date (timestamp)
      - name: maxDate
        in: query
        type: string
        description: Filter by maximum date (timestamp)
      - name: sort
        in: query
        type: string
        description: Sort tickets by column (id, subject, language, country, status, order_no, timestamp)
      - name: page
        in: query
        type: integer
        description: Page number for pagination
      - name: per_page
        in: query
        type: integer
        description: Number of records per page
      - name: format
        in: query
        type: string
        description: Response format (json, yaml, xml)
    responses:
      200:
        description: Successful operation
        schema:
          type: object
          properties:
            tickets:
              type: array
              items:
                $ref: '#/definitions/Ticket'
            pagination:
              $ref: '#/definitions/Pagination'
      400:
        description: Invalid format type
        schema:
          type: object
          properties:
            error:
              type: string
    securityDefinitions:
      Bearer:
        type: apiKey
        name: Authorization
        in: header
        description: Bearer Token
    """
    try:
        session = Session()

        # Filter tickets based on provided parameters
        query = session.query(Ticket)

        # Filter by ID
        id_filter = request.args.get('id')
        if id_filter is not None:
            query = query.filter(Ticket.id == int(id_filter))

        # Filter by other columns (subject, language, country, status, order_no)
        for column in ['subject', 'language', 'country', 'status', 'order_no']:
            column_filter = request.args.get(column)
            if column_filter is not None:
                query = query.filter(getattr(Ticket, column) == column_filter)

        # Filter by date range (timestamp)
        min_date_filter = request.args.get('minDate')
        max_date_filter = request.args.get('maxDate')
        if min_date_filter is not None:
            query = query.filter(Ticket.timestamp >= datetime.strptime(
                min_date_filter, "%Y-%m-%dT%H:%MZ"))
        if max_date_filter is not None:
            query = query.filter(Ticket.timestamp <= datetime.strptime(
                max_date_filter, "%Y-%m-%dT%H:%MZ"))

        # Sort tickets based on provided column
        sort_column = request.args.get('sort')
        if sort_column is not None:
            if sort_column in ['id', 'subject', 'language', 'country', 'status', 'order_no', 'timestamp']:
                query = query.order_by(text(sort_column))

        # Count the total number of records without pagination
        total_records = query.count()

        # Pagination parameters
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 10))
        offset = (page - 1) * per_page

        # Calculate the total number of pages
        total_pages = ceil(total_records / per_page)

        # Apply pagination to the query
        query = query.offset(offset).limit(per_page)

        # Retrieve the filtered and sorted tickets
        tickets = query.all()
        # Prepare the response JSON
        ticket_list = []
        for ticket in tickets:
            ticket_dict = {
                'id': ticket.id,
                'subject': ticket.subject,
                'language': ticket.language,
                'country': ticket.country,
                'status': ticket.status,
                'order_no': ticket.order_no,
                'timestamp': ticket.timestamp
            }
            ticket_list.append(ticket_dict)

        session.close()

        # Create the pagination response
        response = {
            'tickets': ticket_list,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total_pages': total_pages,
                'total_records': total_records
            }
        }

        # Select the format based on the 'format' query parameter
        format_type = request.args.get('format', 'json').lower()

        if format_type == 'json':
            # Return JSON response
            return jsonify(response)
        elif format_type == 'yaml':
            # Convert to YAML and return response
            yaml_data = yaml.dump(response)
            return Response(yaml_data, mimetype='text/yaml')
        elif format_type == 'xml':
            # Convert to XML and return response
            xml_data = dicttoxml(response, custom_root='data', attr_type=False)
            return Response(xml_data, mimetype='application/xml')
        else:
            return jsonify({'error': 'Invalid format type.'}), 400

    except Exception as e:
        return jsonify({'error': str(e)})


@app.route('/tickets', methods=['POST'])
@require_oauth('WRITE')
def insert_ticket():
    """
    Insert ticket endpoint.
    ---
    security:
      - Bearer: []
    parameters:
      - name: file
        in: formData
        type: file
        required: true
        description: CSV file to insert tickets
      - name: format
        in: query
        type: string
        description: Response format (json, yaml, xml)
    responses:
      200:
        description: Successful operation
        schema:
          type: object
          properties:
            success:
              type: string
      400:
        description: Invalid format type
        schema:
          type: object
          properties:
            error:
              type: string
    securityDefinitions:
      Bearer:
        type: apiKey
        name: Authorization
        in: header
        description: Bearer Token
    """
    try:
        session = Session()
        file = request.files['file']

        # Wrap the binary-mode file object with TextIOWrapper to convert it to text mode
        file_wrapper = TextIOWrapper(file, encoding='utf-8')

        # Read the CSV file
        csv_reader = csv.reader(file_wrapper, delimiter=';')

        # Skip the header row if it exists
        next(csv_reader)

        for row in csv_reader:
            ticket_id = row[0]
            timestamp = row[1]
            subject = row[2]
            order_no = row[3]
            language = row[4]
            country = row[5]
            status = row[6].upper()

            # Perform transformations as required
            language_parts = language.split('::')
            language_code = language_parts[-1].lower() if len(
                language_parts) > 1 else 'en'
            country_code = country.split('::')[0].upper() if len(
                country.split('::')) > 1 else 'US'

            # Convert the timestamp to a datetime object
            timestamp = datetime.strptime(timestamp, "%Y-%m-%dT%H:%MZ")

            if status == "PENDING":
                status = "WIP"

            # Check if the status is valid
            if status not in VALID_STATUSES:
                continue  # Skip this ticket and move to the next one

            # Create and insert the Ticket object
            ticket = Ticket(
                id=ticket_id,
                subject=subject,
                language=f'{language_code}-{country_code}',
                country=country_code,
                status=status,
                order_no=order_no,
                timestamp=timestamp
            )
            try:
                session.add(ticket)
                session.commit()
            except IntegrityError as e:
                session.rollback()
                continue  # Skip this ticket and move to the next one

        session.close()
        message = {'message': 'Tickets inserted successfully.'}
        # Select the format based on the 'format' query parameter
        format_type = request.args.get('format', 'json').lower()

        if format_type == 'json':
            # Return JSON response
            return jsonify(message)
        elif format_type == 'yaml':
            # Convert to YAML and return response
            yaml_data = yaml.dump(message)
            return Response(yaml_data, mimetype='text/yaml')
        elif format_type == 'xml':
            # Convert to XML and return response
            xml_data = dicttoxml(message, custom_root='data', attr_type=False)
            return Response(xml_data, mimetype='application/xml')
        else:
            return jsonify({'error': 'Invalid format type.'}), 400
    except Exception as e:
        return jsonify({'error': str(e)})


@app.route('/info', methods=['GET'])
@require_oauth('READ')
def get_info():
    """
    Get info endpoint.
    ---
    security:
      - Bearer: []
    parameters:
      - name: format
        in: query
        type: string
        description: Response format (json, yaml, xml)
    responses:
      200:
        description: Successful operation
        schema:
          type: object
          properties:
            info:
              type: string
      400:
        description: Invalid format type
        schema:
          type: object
          properties:
            error:
              type: string
    securityDefinitions:
      Bearer:
        type: apiKey
        name: Authorization
        in: header
        description: Bearer Token
    """
    try:
        session = Session()

        # Get the most recent ticket
        last_ticket = session.query(Ticket).order_by(
            Ticket.timestamp.desc()).first()

        # Get the older ticket with status OPEN, WIP, or STANDBY
        next_ticket = session.query(Ticket).filter(Ticket.status.in_(
            ['OPEN', 'WIP', 'STANDBY'])).order_by(Ticket.timestamp.asc()).first()

        # Get the top 3 most common subjects and their count
        popular_subjects = session.query(Ticket.subject, func.count(Ticket.subject)).group_by(
            Ticket.subject).order_by(func.count(Ticket.subject).desc()).limit(3).all()

        session.close()

        # Prepare the response data
        response = {
            'lastTicket': {
                'id': last_ticket.id,
                'subject': last_ticket.subject,
                'timestamp': last_ticket.timestamp
            },
            'nextTicket': {
                'id': next_ticket.id,
                'subject': next_ticket.subject,
                'timestamp': next_ticket.timestamp
            },
            'popularSubjects': [{
                'subject': subject,
                'count': count
            } for subject, count in popular_subjects]
        }

        # Select the format based on the 'format' query parameter
        format_type = request.args.get('format', 'json').lower()

        if format_type == 'json':
            # Return JSON response
            return jsonify(response)
        elif format_type == 'yaml':
            # Convert to YAML and return response
            yaml_data = yaml.dump(response)
            return Response(yaml_data, mimetype='text/yaml')
        elif format_type == 'xml':
            # Convert to XML and return response
            xml_data = dicttoxml(response, custom_root='data', attr_type=False)
            return Response(xml_data, mimetype='application/xml')
        else:
            return jsonify({'error': 'Invalid format type.'}), 400

    except Exception as e:
        return jsonify({'error': str(e)})


# Start the Flask app
if __name__ == '__main__':
    app.run()

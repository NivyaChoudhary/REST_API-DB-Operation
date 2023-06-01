# REST_API-DB-Operation
# Ticket API

Ticket API is a Flask-based web application that provides endpoints to manage tickets. It allows users to retrieve tickets, insert tickets from a CSV file, and get information about the tickets.

## Features

- OAuth authentication for secure access to the API.
- Get tickets with various filtering, sorting, and pagination options.
- Insert tickets from a CSV file.
- Retrieve information about tickets such as the most recent ticket, the next ticket with specific statuses, and the top 3 most common subjects.

## Prerequisites

- Python 3.6 or higher
- PostgreSQL database

## Setup

1. Clone the repository

2. Install the dependencies

3. Set up the database

- Create a PostgreSQL database.
- Update the database connection configuration in the code (`DB_HOST`, `DB_NAME`, `DB_USER`, `DB_PASSWORD`) to match your database setup.

4. Run the application

5. The application should now be running on `http://localhost:5000`.

## Endpoints

- `POST /oauth/token`: Generate an access token for authentication.
- `GET /tickets`: Get tickets with various filtering, sorting, and pagination options.
- `POST /tickets`: Insert tickets from a CSV file.
- `GET /info`: Get information about the tickets.

For detailed information about each endpoint, including parameters, responses, and security requirements, refer to the Swagger documentation available at `http://localhost:5000/apidocs`.

## Security

The API uses OAuth 2.0 authentication with Bearer tokens for securing the endpoints. To access the protected endpoints, include the access token in the `Authorization` header as a Bearer token.

## Response Formats

The API supports multiple response formats: JSON, YAML, and XML. To specify the response format, include the `format` query parameter in the request URL. The default format is JSON.


# Collaborative Event Management System - Backend

A FastAPI-based application for managing events, sharing them with collaborators, maintaining version history, and tracking changes. The application uses SQLite as the database and provides endpoints for user authentication, event management, collaboration, version history, and changelog.

## Features

- **User Authentication**: Register, login, logout, and refresh tokens.
- **Event Management**: Create, update, delete, and list events.
- **Collaboration**: Share events with other users and manage permissions.
- **Version History**: Maintain and rollback to previous versions of events.
- **Changelog & Diff**: View a chronological log of changes and compare event versions.

## Requirements

- Python 3.9 or higher
- SQLite
- FastAPI
- Uvicorn

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/your-repo/event-collaboration-api.git
   cd event-collaboration-api
   ```

2. **Create and activate virtual environment**:

   ```bash
   python -m venv env
   source env/bin/activate
   ```

3. **Install dependencies**:

   ```bash
   pip install -r requirements.txt
   ```

4. **Run the application**:

   ```bash
   uvicorn main:app --reload
   ```

5. Access the API documentation:
   - Swagger UI: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
   - ReDoc: [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)

## Endpoints

### Authentication

- **POST** `/api/auth/register`: Register a new user.
- **POST** `/api/auth/login`: Login and get an access token.
- **POST** `/api/auth/refresh`: Refresh the access token.
- **POST** `/api/auth/logout`: Logout the user.

### User Management

- **GET** `/api/users`: Retrieve all users (requires authentication).

### Event Management

- **POST** `/api/events`: Create a new event.
- **GET** `/api/events`: List all events (with optional search).
- **GET** `/api/events/{id}`: Get details of a specific event.
- **PUT** `/api/events/{id}`: Update an event.
- **DELETE** `/api/events/{id}`: Delete an event.
- **POST** `/api/events/batch`: Create multiple events in a batch.

### Collaboration

- **POST** `/api/events/{event_id}/share`: Share an event with another user.
- **GET** `/api/events/{event_id}/permissions`: List all permissions for an event.
- **PUT** `/api/events/{event_id}/permissions/{user_id}`: Update permissions for a user.
- **DELETE** `/api/events/{event_id}/permissions/{user_id}`: Remove access for a user.

### Version History

- **GET** `/api/events/{event_id}/history/{version_id}`: Get a specific version of an event.
- **POST** `/api/events/{event_id}/rollback/{version_id}`: Rollback to a previous version of an event.

### Changelog & Diff

- **GET** `/api/events/{event_id}/changelog`: Get a chronological log of all changes to an event.
- **GET** `/api/events/{event_id}/diff/{version_id1}/{version_id2}`: Get a diff between two versions of an event.

## Database

- **Database**: SQLite (`events.db`)

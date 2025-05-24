from fastapi import FastAPI, Depends, HTTPException, status, Body, Path, Query, Response
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from typing import List, Optional
from uuid import uuid4, UUID
from datetime import datetime, timedelta
from jose import JWTError, jwt
from sqlalchemy import create_engine, Column, String, DateTime, ForeignKey, and_
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, Session
import uuid
from fastapi import Body
from sqlalchemy import JSON

# Database setup
SQLALCHEMY_DATABASE_URL = "sqlite:///./events.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Constants
SECRET_KEY = "supersecret"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# FastAPI App
app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

### Database Models

class UserDB(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)

class EventDB(Base):
    __tablename__ = "events"
    id = Column(String, primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    title = Column(String)
    description = Column(String, nullable=True)
    start_time = Column(DateTime)
    end_time = Column(DateTime)
    created_by = Column(String, ForeignKey("users.id"))

class CollaboratorDB(Base):
    __tablename__ = "collaborators"
    id = Column(String, primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    event_id = Column(String, ForeignKey("events.id"))
    user_id = Column(String, ForeignKey("users.id"))
    role = Column(String)  # e.g., "viewer", "editor"

# Create tables
Base.metadata.create_all(bind=engine)

### Pydantic Models

class User(BaseModel):
    id: UUID
    email: EmailStr
    hashed_password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class Event(BaseModel):
    id: UUID
    title: str
    description: Optional[str] = None
    start_time: datetime
    end_time: datetime
    created_by: UUID

    class Config:
        orm_mode = True

class EventCreate(BaseModel):
    title: str
    description: Optional[str] = None
    start_time: datetime
    end_time: datetime

class EventUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None

class CollaboratorCreate(BaseModel):
    user_id: str  
    role: str     
class CollaboratorOut(BaseModel):
    id: str
    event_id: str
    user_id: str
    role: str

    class Config:
        orm_mode = True

### Dependency

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

### Auth utils

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        if user_id is None:
            raise credentials_exception
        user = db.query(UserDB).filter(UserDB.id == user_id).first()
        if user is None:
            raise credentials_exception
        return user
    except JWTError:
        raise credentials_exception

### Authentication Endpoints

@app.post("/api/auth/register")
def register(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user_exists = db.query(UserDB).filter(UserDB.email == form_data.username).first()
    if user_exists:
        raise HTTPException(status_code=400, detail="Email already registered")
    # NOTE: Add proper password hashing in production
    user = UserDB(email=form_data.username, hashed_password=form_data.password)
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"msg": "User registered"}

@app.post("/api/auth/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(UserDB).filter(UserDB.email == form_data.username, UserDB.hashed_password == form_data.password).first()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid credentials")
    access_token = create_access_token(data={"sub": str(user.id)})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/api/auth/refresh", response_model=Token)
def refresh_token(current_user: UserDB = Depends(get_current_user)):
    access_token = create_access_token(data={"sub": str(current_user.id)})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/api/auth/logout")
def logout(response: Response):
    response.delete_cookie(key="Authorization")
    return {"msg": "Logged out"}

@app.get("/api/users", response_model=List[User])
def get_all_users(db: Session = Depends(get_db), current_user: UserDB = Depends(get_current_user)):
    """
    Retrieve all users from the database.
    """
    # Optional: Restrict access to admin users if needed
    users = db.query(UserDB).all()
    return users

### Event Management Endpoints

@app.post("/api/events", response_model=Event)
def create_event(event: EventCreate, current_user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    new_event = EventDB(
        title=event.title,
        description=event.description,
        start_time=event.start_time,
        end_time=event.end_time,
        created_by=current_user.id
    )
    db.add(new_event)
    db.commit()
    db.refresh(new_event)
    return new_event

@app.get("/api/events", response_model=List[Event])
def list_events(
    skip: int = 0,
    limit: int = 10,
    search: Optional[str] = Query(None),
    current_user: UserDB = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    user_id = str(current_user.id)
    base_query = db.query(EventDB).filter(
        (EventDB.created_by == user_id) |
        (EventDB.id.in_(
            db.query(CollaboratorDB.event_id).filter(CollaboratorDB.user_id == user_id)
        ))
    )
    if search:
        base_query = base_query.filter(EventDB.title.contains(search))
    events = base_query.offset(skip).limit(limit).all()
    return events

@app.get("/api/events/{id}", response_model=Event)
def get_event(id: str, current_user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    event = db.query(EventDB).filter(EventDB.id == id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    user_id = str(current_user.id)
    has_access = (event.created_by == user_id) or db.query(CollaboratorDB).filter(
        CollaboratorDB.event_id == id, CollaboratorDB.user_id == user_id).first()
    if not has_access:
        raise HTTPException(status_code=403, detail="Access denied")
    return event

@app.put("/api/events/{id}", response_model=Event)
def update_event(id: str, event_update: EventUpdate, current_user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    event = db.query(EventDB).filter(EventDB.id == id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    if event.created_by != str(current_user.id):
        raise HTTPException(status_code=403, detail="Only creator can update event")
    for var, value in vars(event_update).items():
        if value is not None:
            setattr(event, var, value)
    db.commit()
    db.refresh(event)
    return event

@app.delete("/api/events/{id}")
def delete_event(id: str, current_user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    event = db.query(EventDB).filter(EventDB.id == id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    if event.created_by != str(current_user.id):
        raise HTTPException(status_code=403, detail="Only creator can delete event")
    db.delete(event)
    db.commit()
    return {"msg": "Event deleted"}

@app.post("/api/events/batch", response_model=List[Event])
def batch_create_events(events: List[EventCreate], current_user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    created_events = []
    for event_data in events:
        new_event = EventDB(
            title=event_data.title,
            description=event_data.description,
            start_time=event_data.start_time,
            end_time=event_data.end_time,
            created_by=current_user.id
        )
        db.add(new_event)
        created_events.append(new_event)
    db.commit()
    for event in created_events:
        db.refresh(event)
    return created_events

# --- Collaboration Endpoints ---

@app.post("/api/events/{event_id}/share")
def share_event(
    event_id: str,
    collaborator: CollaboratorCreate,
    db: Session = Depends(get_db),
    user: UserDB = Depends(get_current_user)
):
    """
    Share an event with another user by adding them as a collaborator.
    """
    event = db.query(EventDB).filter(EventDB.id == event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    if event.created_by != str(user.id):
        raise HTTPException(status_code=403, detail="Only the creator can share the event")
    
    collab = CollaboratorDB(
        event_id=event_id,
        user_id=str(collaborator.user_id),
        role=collaborator.role
    )
    db.add(collab)
    db.commit()
    db.refresh(collab)
    return {"msg": "User shared", "collaborator": collab}


@app.get("/api/events/{event_id}/permissions", response_model=List[CollaboratorOut])
def list_permissions(
    event_id: str,
    db: Session = Depends(get_db),
    user: UserDB = Depends(get_current_user)
):
    """
    List all permissions for a specific event.
    """
    event = db.query(EventDB).filter(EventDB.id == event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    if event.created_by != str(user.id):
        raise HTTPException(status_code=403, detail="Only the creator can view permissions")
    
    permissions = db.query(CollaboratorDB).filter(CollaboratorDB.event_id == event_id).all()
    return permissions


@app.put("/api/events/{event_id}/permissions/{user_id}")
def update_permission(
    event_id: str,
    user_id: str,
    role: str = Body(...),
    db: Session = Depends(get_db),
    user: UserDB = Depends(get_current_user)
):
    """
    Update permissions for a specific user on an event.
    """
    event = db.query(EventDB).filter(EventDB.id == event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    if event.created_by != str(user.id):
        raise HTTPException(status_code=403, detail="Only the creator can update permissions")
    
    collab = db.query(CollaboratorDB).filter(
        CollaboratorDB.event_id == event_id,
        CollaboratorDB.user_id == user_id
    ).first()
    if not collab:
        raise HTTPException(status_code=404, detail="Collaborator not found")
    
    collab.role = role
    db.commit()
    return {"msg": "Permission updated"}


@app.delete("/api/events/{event_id}/permissions/{user_id}")
def remove_permission(
    event_id: str,
    user_id: str,
    db: Session = Depends(get_db),
    user: UserDB = Depends(get_current_user)
):
    """
    Remove access for a specific user from an event.
    """
    event = db.query(EventDB).filter(EventDB.id == event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    if event.created_by != str(user.id):
        raise HTTPException(status_code=403, detail="Only the creator can remove permissions")
    
    collab = db.query(CollaboratorDB).filter(
        CollaboratorDB.event_id == event_id,
        CollaboratorDB.user_id == user_id
    ).first()
    if not collab:
        raise HTTPException(status_code=404, detail="Collaborator not found")
    
    db.delete(collab)
    db.commit()
    return {"msg": "Permission removed"}


# Add a new table for event version history
class EventVersionDB(Base):
    __tablename__ = "event_versions"
    id = Column(String, primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    event_id = Column(String, ForeignKey("events.id"))
    version_data = Column(JSON)  # Stores the event data as JSON
    created_at = Column(DateTime, default=datetime.utcnow)

# Create the new table
Base.metadata.create_all(bind=engine)

@app.get("/api/events/{event_id}/history/{version_id}", response_model=Event)
def get_event_version(
    event_id: str,
    version_id: str,
    db: Session = Depends(get_db),
    current_user: UserDB = Depends(get_current_user)
):
    """
    Get a specific version of an event.
    """
    # Check if the event exists and the user has access
    event = db.query(EventDB).filter(EventDB.id == event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    user_id = str(current_user.id)
    has_access = (event.created_by == user_id) or db.query(CollaboratorDB).filter(
        CollaboratorDB.event_id == event_id, CollaboratorDB.user_id == user_id
    ).first()
    if not has_access:
        raise HTTPException(status_code=403, detail="Access denied")

    # Fetch the specific version
    version = db.query(EventVersionDB).filter(
        EventVersionDB.event_id == event_id,
        EventVersionDB.id == version_id
    ).first()
    if not version:
        raise HTTPException(status_code=404, detail="Version not found")

    return version.version_data


@app.post("/api/events/{event_id}/rollback/{version_id}")
def rollback_event_version(
    event_id: str,
    version_id: str,
    db: Session = Depends(get_db),
    current_user: UserDB = Depends(get_current_user)
):
    """
    Rollback to a previous version of an event.
    """
    # Check if the event exists and the user is the creator
    event = db.query(EventDB).filter(EventDB.id == event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    if event.created_by != str(current_user.id):
        raise HTTPException(status_code=403, detail="Only the creator can rollback the event")

    # Fetch the specific version
    version = db.query(EventVersionDB).filter(
        EventVersionDB.event_id == event_id,
        EventVersionDB.id == version_id
    ).first()
    if not version:
        raise HTTPException(status_code=404, detail="Version not found")

    # Rollback the event to the previous version
    version_data = version.version_data
    event.title = version_data["title"]
    event.description = version_data["description"]
    event.start_time = version_data["start_time"]
    event.end_time = version_data["end_time"]

    db.commit()
    db.refresh(event)
    return {"msg": "Event rolled back to the specified version", "event": event}


# Helper function to save event versions
def save_event_version(event: EventDB, db: Session):
    version_data = {
        "title": event.title,
        "description": event.description,
        "start_time": event.start_time,
        "end_time": event.end_time,
        "created_by": event.created_by
    }
    version = EventVersionDB(event_id=event.id, version_data=version_data)
    db.add(version)
    db.commit()

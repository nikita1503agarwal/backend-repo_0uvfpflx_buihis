"""
Database Schemas for Ternak Lele

Each Pydantic model maps to a MongoDB collection using the lowercase
class name as the collection name.
"""
from typing import Optional, List
from pydantic import BaseModel, Field, EmailStr
from datetime import datetime


class User(BaseModel):
    """
    Collection: "user"
    """
    name: str = Field(..., description="Full name")
    email: EmailStr = Field(..., description="Unique email address")
    password_hash: str = Field(..., description="Password hash (bcrypt/argon2)")
    avatar_url: Optional[str] = Field(None, description="Avatar image URL")
    bio: Optional[str] = Field("", description="Short bio")
    is_active: bool = Field(True, description="Whether user is active")


class BlogPost(BaseModel):
    """
    Collection: "blogpost"
    """
    title: str
    content: str
    author_id: str
    slug: str
    tags: List[str] = []
    status: str = Field("published", description="draft|published")
    view_count: int = 0
    likes: int = 0
    published_at: Optional[datetime] = None


class HitCounter(BaseModel):
    """
    Collection: "hitcounter"
    Tracks global hit counts for the app and optionally per route.
    """
    key: str = Field(..., description="counter key, e.g. 'total' or route path")
    count: int = 0

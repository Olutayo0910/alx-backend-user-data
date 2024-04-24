#!/usr/bin/env python3
"""
User module - Defines the SQLAlchemy User model.
"""

from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String

Base = declarative_base()


class User(Base):
    """
    User class representing a user in the database.

    Attributes:
        id (int): The primary key of the user.
        email (str): The email address of the user.
        hashed_password (str): The hashed password of the user.
        session_id (str, optional): The session ID of the user.
        reset_token (str, optional): The reset token of the user.
    """

    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    email = Column(String(250), nullable=False)
    hashed_password = Column(String(250), nullable=False)
    session_id = Column(String(250), nullable=True)
    reset_token = Column(String(250), nullable=True)

    def __repr__(self):
        """
        String representation of the User object.

        Returns:
            str: String representation.
        """
        return f"User: id={self.id}"
